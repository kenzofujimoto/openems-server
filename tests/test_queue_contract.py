"""Contract tests every Queue implementation must satisfy.

InMemoryQueue runs always. RedisQueue runs only when OPENEMS_TEST_REDIS is set:

    docker run --rm -p 6379:6379 redis:7
    OPENEMS_TEST_REDIS=redis://localhost:6379/0 pytest
"""

from __future__ import annotations

import os

import pytest

from app.queue import InMemoryQueue, RedisQueue


def _make_inmemory():
    return InMemoryQueue()


def _make_redis():
    url = os.environ.get("OPENEMS_TEST_REDIS")
    if not url:
        pytest.skip("OPENEMS_TEST_REDIS not set; skipping RedisQueue contract test")
    q = RedisQueue(url, prefix="test-queue:")
    # clean slate
    q._redis.flushdb()  # noqa: SLF001 - test-only reset
    return q


@pytest.fixture(params=[_make_inmemory, _make_redis], ids=["inmemory", "redis"])
def queue(request):
    return request.param()


def test_push_then_pull_returns_messages_in_order(queue) -> None:
    queue.push("ep-1", {"n": 1})
    queue.push("ep-1", {"n": 2})
    assert queue.pull("ep-1") == [{"n": 1}, {"n": 2}]


def test_pull_drains_the_topic(queue) -> None:
    queue.push("ep-1", {"n": 1})
    queue.pull("ep-1")
    assert queue.pull("ep-1") == []


def test_topics_are_isolated(queue) -> None:
    queue.push("ep-1", {"n": 1})
    queue.push("ep-2", {"n": 9})
    assert queue.pull("ep-2") == [{"n": 9}]
    assert queue.pull("ep-1") == [{"n": 1}]


def test_empty_topic_returns_empty_list(queue) -> None:
    assert queue.pull("never-used") == []
