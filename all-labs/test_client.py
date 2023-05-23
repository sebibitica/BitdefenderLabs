import asyncio
import copy
import hashlib
import json
import random
import string
import sys
import time
import uuid
from argparse import ArgumentParser
from contextlib import nullcontext
from pathlib import Path

import aiohttp as aiohttp
import pydantic as pydantic

ROOT_PATHS = ['srv', 'opt', 'sys', 'home', 'var', 'etc', 'tmp']
SECOND_LEVEL_PATHS = ['bitdefender', 'liga-ac-labs', 'bd', 'ceva', 'un folder cu spații și unicode']
SUBDIR_CHARS = list(string.ascii_letters + string.digits)
FILE_CHARS = list(string.ascii_letters + string.digits + ', .+-!')
EXTENSION_CHARS = list(string.ascii_letters)
EXTENSIONS = ['exe', 'elf', 'so', 'png', 'jpg', 'jpeg', 'mp3', 'doc', 'docx', 'pptx', 'odf', 'pdf', 'js', 'py']


def random_string(chars, min_chars, max_chars):
    target_len = random.randint(min_chars, max_chars)
    return ''.join(random.choices(chars, k=target_len))


def generate_path():
    components = [
        random.choice(ROOT_PATHS),
        random.choice(SECOND_LEVEL_PATHS),
    ]

    for _ in range(random.randint(1, 3)):
        components.append(random_string(SUBDIR_CHARS, 2, 7))

    filename = random_string(FILE_CHARS, 3, 10)
    extension_type = random.randint(0, 4)
    if extension_type == 0:
        filename += f'.{random_string(EXTENSION_CHARS, 1, 4)}'
    elif extension_type == 1:
        pass
    else:
        filename += f'.{random.choice(EXTENSIONS)}'

    components.append(filename)
    return '/' + '/'.join(components)


def generate_md5():
    return ''.join(random.choices(string.hexdigits, k=32))


def generate_file():
    file_len = random.randint(160, 1_000_000)
    file_conents = random.randbytes(file_len)
    file_md5 = hashlib.md5(file_conents).hexdigest()
    return file_conents, file_md5


class VeridctModel(pydantic.BaseModel):
    hash: str
    risk_level: int


class ResponseModel(pydantic.BaseModel):
    file: VeridctModel
    process: VeridctModel


class TaskContext:
    def __init__(self, max_concurrent: int):
        self.pending = set()
        self.max_concurrent = max_concurrent

    async def __aenter__(self):
        return self

    async def add_task(self, task):
        self.pending.add(task)
        if len(self.pending) < self.max_concurrent:
            return

        await self.await_pending()

    async def await_pending(self):
        if not self.pending:
            return

        done, self.pending = await asyncio.wait(self.pending, return_when=asyncio.FIRST_COMPLETED)

        err = None
        for fut in done:  # type: asyncio.Future
            try:
                # retrieve all task exceptions
                fut.result()
            except BaseException as e:
                err = e

        if err is not None:
            # throw last exception
            raise err

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # for task in self.pending:
        #     task.cancel()

        while self.pending:
            await self.await_pending()


async def send_event(session: aiohttp.ClientSession, filesystem: dict, url: str, event: dict):
    async with session.post(url + '/events/', json=event) as resp:
        text = await resp.text()
        try:
            result = ResponseModel.parse_raw(text)
        except pydantic.ValidationError as e:
            print(f'invalid response from server: {text} - {e}')
            sys.exit(1)

    file_event = event["file"]
    print(f'event {file_event["file_hash"]} -> {result.dict()}')
    expected_verdict = {}
    for verdict in (result.file, result.process):
        risk_level = verdict.risk_level
        if risk_level == -1:
            form = aiohttp.FormData()
            form.add_field('file', filesystem[verdict.hash])
            async with session.post(url + '/scan_file/', data=form) as resp:
                text = await resp.text()
                try:
                    upload_result = VeridctModel.parse_raw(text)
                except pydantic.ValidationError as e:
                    print(f'invalid response from server: {text} - {e}')
                    sys.exit(1)
                print(f'\tupload {verdict.hash} -> {upload_result}')
                if verdict.hash != upload_result.hash:
                    print(f'\t\tERROR! hash mismatch in upload response')
                risk_level = upload_result.risk_level

        expected_verdict[verdict.hash] = risk_level

    # test: send event again; should return saved verdicts
    async with session.post(url + '/events/', json=event) as resp:
        result = ResponseModel.parse_raw(await resp.text())
    for verdict in (result.file, result.process):
        if verdict.risk_level != expected_verdict[verdict.hash]:
            print(f'\tERROR! risk level for {verdict.hash} was not saved!; '
                  f'\n\t\t{expected_verdict=}\n\t\t{verdict=}')


async def main():
    parser = ArgumentParser()
    parser.add_argument('--seed', type=int, help='seed that can be used to get reproducible results')
    parser.add_argument('--dump', type=Path, help='dump events to json file')
    parser.add_argument('--port', type=int, help='send events to server running on this port')
    parser.add_argument('-n', '--count', type=int, help='how many events to generate', default=20)
    parser.add_argument('-p', '--parallel', type=int, help='how many requests to send in parallel', default=1)
    args = parser.parse_args()

    if not args.dump and not args.port:
        parser.error(f'either --port or --dump is required')

    seed = args.seed or int(str(int(time.monotonic() * 1000)).rstrip('0') or '42') % 100_000
    random.seed(seed)
    print(f'random seed is: {seed}')

    device_id = str(uuid.UUID(int=random.getrandbits(128), version=4))
    base_time = 1681813841216
    current_time = base_time + 86400 * 24 * 7 + random.randint(0, 86400)

    if not args.count > 0:
        parser.error(f'count must be positive')
    num_programs = random.randint(2, min(max(args.count // 2, 2), 25))
    num_files = random.randint(max(args.count // 7, 1), max(args.count // 3, 1))
    print(f'{num_files=} {num_programs=}')

    filesystem = {}
    programs = []
    for _ in range(num_programs):
        file_contents, file_md5 = generate_file()
        filesystem[file_md5] = file_contents
        programs.append({
            "path": generate_path(),
            "hash": file_md5,
            "pid": random.randint(800, 140000),
        })

    files = []
    for _ in range(num_files):
        file_contents, file_md5 = generate_file()
        filesystem[file_md5] = file_contents
        files.append({
            "file_hash": file_md5,
            "file_path": generate_path(),
            "time": {
                "m": random.randint(base_time, current_time)
            }
        })

    url = f'http://localhost:{args.port or 8000}'
    with (open(args.dump, 'w', encoding='utf-8') if args.dump else nullcontext()) as f:
        loop = asyncio.get_running_loop()
        async with aiohttp.ClientSession() as session, TaskContext(max_concurrent=args.parallel) as context:
            for _ in range(args.count):
                access_time = current_time
                current_time += random.randint(0, 30)

                file_event = copy.deepcopy(random.choice(files))
                file_event["time"]["a"] = access_time

                program_event = copy.deepcopy(random.choice(programs))

                event = {
                    "device": {
                        "id": device_id,
                        "os": "linux"
                    },
                    "file": file_event,
                    "last_access": program_event,
                }

                if args.dump:
                    f.write(json.dumps(event) + '\n')

                if args.port:
                    coro = send_event(session, filesystem=filesystem, url=url, event=event)
                    await context.add_task(loop.create_task(coro))


if __name__ == '__main__':
    asyncio.run(main())