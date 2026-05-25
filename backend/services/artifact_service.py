"""Artifact store abstraction — MinIO/S3 backend."""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import AsyncIterable
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError

from config import settings


@dataclass
class ArtifactMeta:
    path: str
    size: int
    mime_type: str
    created_at: datetime


class ArtifactStore(ABC):
    @abstractmethod
    async def put(self, path: str, data: bytes) -> str: ...

    @abstractmethod
    async def get(self, path: str) -> bytes: ...

    @abstractmethod
    async def exists(self, path: str) -> bool: ...

    @abstractmethod
    async def list_prefix(self, prefix: str) -> list[ArtifactMeta]: ...

    @abstractmethod
    async def delete(self, path: str) -> None: ...

    @abstractmethod
    async def presign_get(self, path: str, expires: int = 300) -> str: ...


class MinIOArtifactStore(ArtifactStore):
    def __init__(self) -> None:
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name="us-east-1",
        )
        self._bucket = settings.s3_bucket

    def _run_sync(self, fn, *args, **kwargs):  # type: ignore[no-untyped-def]
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(None, lambda: fn(*args, **kwargs))

    async def put(self, path: str, data: bytes) -> str:
        await self._run_sync(self._client.put_object, Bucket=self._bucket, Key=path, Body=data)
        return path

    async def get(self, path: str) -> bytes:
        response = await self._run_sync(self._client.get_object, Bucket=self._bucket, Key=path)
        return response["Body"].read()

    async def exists(self, path: str) -> bool:
        try:
            await self._run_sync(self._client.head_object, Bucket=self._bucket, Key=path)
            return True
        except ClientError:
            return False

    async def list_prefix(self, prefix: str) -> list[ArtifactMeta]:
        response = await self._run_sync(
            self._client.list_objects_v2, Bucket=self._bucket, Prefix=prefix
        )
        items = []
        for obj in response.get("Contents", []):
            items.append(
                ArtifactMeta(
                    path=obj["Key"],
                    size=obj["Size"],
                    mime_type="application/octet-stream",
                    created_at=obj["LastModified"],
                )
            )
        return items

    async def delete(self, path: str) -> None:
        await self._run_sync(self._client.delete_object, Bucket=self._bucket, Key=path)

    async def presign_get(self, path: str, expires: int = 300) -> str:
        url = await self._run_sync(
            self._client.generate_presigned_url,
            "get_object",
            Params={"Bucket": self._bucket, "Key": path},
            ExpiresIn=expires,
        )
        return url


@lru_cache(maxsize=1)
def get_artifact_store() -> ArtifactStore:
    return MinIOArtifactStore()
