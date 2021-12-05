import typing

from pydantic import BaseModel


__all__ = ["Task"]


class Task(BaseModel):

    id: int
    arch: str


class Artifact(BaseModel):

    name: str
    type: str
    href: str
