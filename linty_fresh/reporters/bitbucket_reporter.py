import argparse
import asyncio
import json
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, MutableMapping, Optional, Set, TypeVar

import requests

from linty_fresh.problem import Problem, TestProblem


class BitbucketClient:

    def __init__(self, auth_token):
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Basic {}'.format(auth_token),
        }

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

    # clean up anything you need to clean up
    async def get(self, url, **kwargs):
        return requests.get(url, headers=self.headers, **kwargs)

    async def post(self, url, **kwargs):
        return requests.post(url, headers=self.headers, **kwargs)

    async def delete(self, url, **kwargs):
        return requests.delete(url, headers=self.headers, **kwargs)


PR_URL_REGEX = re.compile(r'https?://.*?bitbucket.org/'
                          r'(?:repos/)?'
                          r'(?P<organization>[^/]*)/'
                          r'(?P<repo>[^/]*)/pull-requests?/'
                          r'(?P<pr_number>\d*)')
HUNK_REGEX = re.compile(r'@@ \-\d+,\d+ \+(\d+),\d+ @@')
FILE_START_REGEX = re.compile(r'\+\+\+ b/(.*)')
LINK_REGEX = re.compile(r'<(?P<url>.+)>; rel="(?P<rel>\w+)"')
NEW_FILE_SECTION_START = 'diff --git a'
MAX_LINT_ERROR_REPORTS = 10


class HadLintErrorsException(Exception):
    pass


class ExistingBitbucketMessage(object):
    def __init__(self,
                 comment_id: Optional[int],
                 path: str,
                 position: int,
                 body: str) -> None:
        self.comment_id = comment_id
        self.path = path
        self.position = position
        self.body = body

    def __hash__(self):
        return hash((self.path, self.position, self.body))

    def __eq__(self, other):
        if isinstance(self, other.__class__):
            return (self.path == other.path and
                    self.position == other.position and
                    self.body == other.body)
        return False


GenericProblem = TypeVar('GenericProblem', Problem, TestProblem)


class BitbucketReporter(object):

    def __init__(self,
                 auth_token: str,
                 organization: str,
                 repo: str,
                 pr_number: int,
                 commit: str,
                 delete_previous_comments: bool) -> None:
        self.auth_token = auth_token
        self.organization = organization
        self.repo = repo
        self.pr = pr_number
        self.commit = commit
        self.delete_previous_comments = delete_previous_comments

    async def report(self, linter_name: str,
                     problems: List[GenericProblem]) -> None:

        client_session = BitbucketClient(auth_token=self.auth_token)
        # await self.delete_all_existing_pr_messages(client_session, linter_name)
        # return

        if not problems:
            grouped_problems = {}
        elif isinstance(list(problems)[0], TestProblem):
            grouped_problems = TestProblem.group_by_group(problems)
        else:
            grouped_problems = Problem.group_by_path_and_line(problems)

        (line_map, existing_messages) = await asyncio.gather(
            self.create_line_to_position_map(client_session),
            self.get_existing_pr_messages(client_session, linter_name))

        lint_errors = 0
        review_comment_awaitable = []
        pr_url = self._get_pr_url()
        no_matching_line_number = []
        for location, problems_for_line in grouped_problems:
            message_for_line = ['{0} says:'.format(linter_name), '']

            reported_problems_for_line = set()

            path = location[0]
            line_number = location[1]

            position = line_map.get(path, {}).get(line_number, None)
            if position is None and path in line_map:
                file_map = line_map[path]
                closest_line = min(file_map.keys(),
                                   key=lambda x: abs(x - line_number))
                position = file_map[closest_line]
                message_for_line.append('(From line {})'.format(
                    line_number))
            message_for_line.append('```')
            if position is not None:
                for problem in problems_for_line:
                    if problem.message not in reported_problems_for_line:
                        message_for_line.append(problem.message)
                        reported_problems_for_line.add(problem.message)
                message_for_line.append('```')
                message = '\n'.join(message_for_line)
                try:
                    existing_messages.remove(
                        ExistingBitbucketMessage(None, path, position,
                                                 message))
                except KeyError:
                    lint_errors += 1
                    if lint_errors <= MAX_LINT_ERROR_REPORTS:
                        data = json.dumps(
                            {'content': {'raw': message}, 'inline': {'from': position, 'to': position, 'path': path}})
                        review_comment_awaitable.append(client_session.post(pr_url, data=data))
            else:
                no_matching_line_number.append((location,
                                                problems_for_line))

        if lint_errors > MAX_LINT_ERROR_REPORTS:
            message = """{0} says:

Too many lint errors to report inline!  {1} lines have a problem.
Only reporting the first {2}.""".format(
                linter_name, lint_errors, MAX_LINT_ERROR_REPORTS)
            data = json.dumps({
                'body': message
            })
            review_comment_awaitable.append(
                asyncio.ensure_future(client_session.post(
                    self._get_issue_url(),
                    data=data)))
        if self.delete_previous_comments:
            for message in existing_messages:
                review_comment_awaitable.append(
                    asyncio.ensure_future(client_session.delete(
                        self._get_delete_pr_comment_url(
                            self.pr, message.comment_id))))

        if no_matching_line_number:
            no_matching_line_messages = []
            for location, problems_for_line in no_matching_line_number:
                lint_errors += 1
                path = location[0]
                line_number = location[1]
                no_matching_line_messages.append(
                    '{0}:{1}:'.format(path, line_number))
                for problem in problems_for_line:
                    no_matching_line_messages.append('\t{0}'.format(
                        problem.message))
            message = ('{0} says: I found some problems with lines not '
                       'modified by this commit:\n```\n{1}\n```'.format(
                linter_name,
                '\n'.join(no_matching_line_messages)))
            data = json.dumps({
                'body': message
            })
            review_comment_awaitable.append(
                asyncio.ensure_future(client_session.post(
                    self._get_issue_url(), data=data)))

        responses = await asyncio.gather(
            *review_comment_awaitable
        )  # type: List[requests.models.Response]
        for response in responses:
            response.close()

        if lint_errors > 0:
            raise HadLintErrorsException()

    async def create_line_to_position_map(
            self, client_session: BitbucketClient
    ) -> MutableMapping[str, Dict[int, int]]:
        result = defaultdict(dict)  # type: MutableMapping[str, Dict[int, int]]
        current_file = ''
        position = -1
        right_line_number = -1

        url = ('https://api.bitbucket.org/2.0/repositories/'
               '{organization}/{repo}/pullrequests/{pr}'.format(
            organization=self.organization,
            repo=self.repo,
            pr=self.pr))

        response = await client_session.get(url)

        # Collect the entire response before reading it. If you iterate
        # over lines instead, very long lines cause exceptions
        diff_url = self._get_diff_url()
        response = await client_session.get(diff_url)
        content = response.content

        for line in content.splitlines():
            line = line.decode()
            file_match = FILE_START_REGEX.match(line)

            if file_match:
                current_file = file_match.groups()[0].strip()
                right_line_number = -1
                position = -1

            if current_file and not file_match:
                position += 1
                hunk_match = HUNK_REGEX.match(line)
                if hunk_match:
                    right_line_number = int(hunk_match.groups()[0]) - 1
                elif not line.startswith('-'):
                    right_line_number += 1
                    result[current_file][right_line_number] = position
        return result

    def _get_pr_url(self) -> str:
        return ('https://api.bitbucket.org/2.0/repositories/'
                '{organization}/{repo}/pullrequests/{pr}/comments'.format(
            organization=self.organization,
            repo=self.repo,
            pr=self.pr))

    def _get_commit_url(self) -> str:
        return ('https://api.bitbucket.org/2.0/repositories/'
                '{organization}/{repo}/commit/{commit}'.format(
            organization=self.organization,
            repo=self.repo,
            commit=self.commit))

    def _get_issue_url(self) -> str:
        return ('https://api.bitbucket.org/2.0/repositories/'
                '{organization}/{repo}/issues/{pr}/comments'.format(
            organization=self.organization,
            repo=self.repo,
            pr=self.pr))

    def _get_diff_url(self) -> str:
        return ('https://api.bitbucket.org/2.0/repositories/'
                '{organization}/{repo}/diff/{commit}'.format(
            organization=self.organization,
            repo=self.repo,
            commit=self.commit))

    def _get_delete_pr_comment_url(self, comment_id: int) -> str:
        return ('https://api.bitbucket.org/2.0/repositories/'
                '{organization}/{repo}/pullrequests/{pull_request_id}/comments/{comment_id}'.format(
            organization=self.organization,
            repo=self.repo,
            pull_request_id=self.pr,
            comment_id=comment_id))

    async def get_existing_pr_messages(
            self, client_session: BitbucketClient, linter_name: str
    ) -> Set[ExistingBitbucketMessage]:
        url = self._get_pr_url() + "?pagelen=100"
        existing_messages = set()  # type: Set[ExistingBitbucketMessage]
        messages_json = await self._fetch_message_json_from_url(
            client_session, url, linter_name)

        for comment in messages_json:
            body = comment['content']['raw']
            if not self._is_linter_message(body, linter_name):
                continue
            existing_messages.add(
                ExistingBitbucketMessage(comment['id'],
                                         comment['inline']['path'],
                                         comment['inline']['to'] or comment['inline']['from'],
                                         body))

        return existing_messages


    async def delete_all_existing_pr_messages(
            self, client_session: BitbucketClient, linter_name: str
    ) -> None:
        url = self._get_pr_url() + "?pagelen=100"
        messages_json = await self._fetch_message_json_from_url(
            client_session, url, linter_name)

        awaitable_array = []

        for comment in messages_json:
            body = comment['content']['raw']
            if not self._is_linter_message(body, linter_name):
                continue
            comment_id = comment['id']
            url = self._get_delete_pr_comment_url(comment_id)
            awaitable_array.append(asyncio.ensure_future(client_session.delete(url)))

        responses = await asyncio.gather(
            *awaitable_array
        )  # type: List[requests.models.Response]
        for response in responses:
            response.close()

    @staticmethod
    async def _fetch_message_json_from_url(
            client_session, url, linter_name
    ) -> [Any]:
        messages_json = []
        response = await client_session.get(url)  # type: requests.models.Response

        if response.status_code == 200:
            messages = response.json()
            messages_json += messages.pop('values')

        next_url = BitbucketReporter._find_next_url(response)

        if next_url:
            messages_json += BitbucketReporter._fetch_message_json_from_url(
                client_session, next_url, linter_name)

        return messages_json

    @staticmethod
    def _find_next_url(response: requests.models.Response) -> str:
        if 'link' in response.headers:
            links = response.headers['link'].split(',')
            for link in links:
                match = LINK_REGEX.match(link)
                if match and match.group('rel') == 'next':
                    return match.group('url')

    @staticmethod
    def _is_linter_message(text: str, linter_name: str) -> bool:
        return text.startswith('{} says:'.format(linter_name))


def register_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--pr_url',
                        type=str,
                        help='The URL for the Pull Request for this commit.')
    parser.add_argument('--commit',
                        type=str,
                        help='The commit being linted.')


def create_reporter(args: Any) -> BitbucketReporter:
    if not args.pr_url or not args.commit:
        raise Exception('Must specify both a pr_url and a commit to use the '
                        'bitbucket reporter.')
    auth_token = os.getenv('BITBUCKET_AUTH_TOKEN')
    if not auth_token:
        raise Exception('Environment Variable $BITBUCKET_AUTH_TOKEN must be set '
                        'to use the bitbucket reporter.')
    match = PR_URL_REGEX.match(args.pr_url)
    if not match:
        raise Exception("{} doesn't appear to be a valid bitbucket pr url".format(
            args.pr_url))

    groups = match.groupdict()
    return BitbucketReporter(auth_token,
                             groups['organization'],
                             groups['repo'],
                             int(groups['pr_number']),
                             args.commit,
                             args.delete_previous_comments)
