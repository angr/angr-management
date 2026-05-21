from __future__ import annotations

import os
import tarfile
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass


class ArchiveError(Exception):
    """Base class for archive loading errors."""


class ArchivePasswordRequired(ArchiveError):
    """Raised when a member requires a password and none was supplied."""


class ArchiveInvalidPassword(ArchiveError):
    """Raised when a supplied archive password is rejected."""


@dataclass(frozen=True)
class ArchiveMember:
    """A single file entry inside an archive."""

    name: str
    size: int
    encrypted: bool = False


class Archive(ABC):
    """Base class for archive format handlers."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise ArchiveError("Archive is closed")

    @classmethod
    @abstractmethod
    def is_type(cls, path: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def list_members(self) -> list[ArchiveMember]:
        raise NotImplementedError

    @abstractmethod
    def extract(self, member: str, dest_dir: str, password: str | None = None) -> str:
        raise NotImplementedError

    def close(self) -> None:
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ZipArchive(Archive):
    """Handler for ZIP archives."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        try:
            self._handle = zipfile.ZipFile(path, "r")  # pylint: disable=consider-using-with
        except (zipfile.BadZipFile, OSError) as e:
            raise ArchiveError(f"Failed to open ZIP archive: {e}") from e

    @classmethod
    def is_type(cls, path: str) -> bool:
        return zipfile.is_zipfile(path)

    def list_members(self) -> list[ArchiveMember]:
        self._ensure_open()
        try:
            return [
                ArchiveMember(i.filename, i.file_size, encrypted=bool(i.flag_bits & 0x1))
                for i in self._handle.infolist()
                if not i.is_dir()
            ]
        except (zipfile.BadZipFile, OSError) as e:
            raise ArchiveError(f"Failed to read ZIP archive: {e}") from e

    def extract(self, member: str, dest_dir: str, password: str | None = None) -> str:
        self._ensure_open()
        try:
            info = self._handle.getinfo(member)
            if info.flag_bits & 0x1 and password is None:
                raise ArchivePasswordRequired("Password required for encrypted ZIP member")

            pwd = password.encode("utf-8") if password is not None else None
            return self._handle.extract(member, dest_dir, pwd=pwd)

        except RuntimeError as e:
            message = str(e).lower()
            if "bad password" in message:
                raise ArchiveInvalidPassword("Incorrect password or unsupported ZIP encryption") from e
            if "password required" in message or "encrypted" in message:
                raise ArchivePasswordRequired("Password required for encrypted ZIP member") from e
            raise ArchiveError(f"Failed to extract ZIP member: {e}") from e

        except (KeyError, zipfile.BadZipFile, OSError) as e:
            raise ArchiveError(f"Failed to extract ZIP member: {e}") from e

    def close(self) -> None:
        super().close()
        self._handle.close()


class TarArchive(Archive):
    """Handler for TAR archives (including compressed variants)."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        try:
            self._handle = tarfile.TarFile.open(path, "r:*")  # pylint: disable=consider-using-with
        except (tarfile.TarError, OSError) as e:
            raise ArchiveError(f"Failed to open TAR archive: {e}") from e

    @classmethod
    def is_type(cls, path: str) -> bool:
        return tarfile.is_tarfile(path)

    def list_members(self) -> list[ArchiveMember]:
        self._ensure_open()
        try:
            return [ArchiveMember(m.name, m.size, encrypted=False) for m in self._handle.getmembers() if m.isfile()]
        except (tarfile.TarError, OSError) as e:
            raise ArchiveError(f"Failed to read TAR archive: {e}") from e

    def extract(self, member: str, dest_dir: str, password: str | None = None) -> str:
        self._ensure_open()
        try:
            self._handle.extract(member, dest_dir, filter="data")
        except (tarfile.TarError, OSError) as e:
            raise ArchiveError(f"Failed to extract TAR member: {e}") from e
        return os.path.join(dest_dir, member)

    def close(self) -> None:
        super().close()
        self._handle.close()


ARCHIVES = [ZipArchive, TarArchive]


def get_archive_object(file_path: str) -> Archive:
    for archive_cls in ARCHIVES:
        if archive_cls.is_type(file_path):
            return archive_cls(file_path)
    raise ArchiveError("Unsupported or invalid archive format")


def is_archive(file_path: str) -> bool:
    return any(archive_cls.is_type(file_path) for archive_cls in ARCHIVES)
