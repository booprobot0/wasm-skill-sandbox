from typing import TypeVar, Generic, Union, Optional, Protocol, Tuple, List, Any, Self
from enum import Flag, Enum, auto
from dataclasses import dataclass
from abc import abstractmethod
import weakref

from ..types import Result, Ok, Err, Some


class Scanner(Protocol):

    @abstractmethod
    def scan_code(self, code: str) -> str:
        """
        Analyze code for security issues
        Returns JSON with findings and safety score
        """
        raise NotImplementedError


