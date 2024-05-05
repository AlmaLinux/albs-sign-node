from pydantic import BaseModel


__all__ = ["Task", "Artifact"]


class Task(BaseModel):

    id: int
    arch: str


class Artifact(BaseModel):

    name: str
    type: str
    href: str
    sha256: str
