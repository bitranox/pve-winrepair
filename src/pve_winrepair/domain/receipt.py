"""The repair receipt: the image build a repair's prepare step measured, for apply to verify against.

The build an in-place repair installs is the build of the WIM image it stages, which only the
guest can read (``prepare`` reports it). A repair records it in a receipt per VM; apply reads that
receipt before it touches the guest and refuses without one, so the build it verifies is always
the one this VM's media carried, never a constant that holds for one media release only.

The receipt also records the build the guest ran before the upgrade and its InstallDate. Media may
carry the very build the guest already runs (the WIM gate allows it), and a rolled-back upgrade
returns to that build: for such a repair, apply also requires InstallDate to change across the
apply reboot (:meth:`RepairReceipt.same_build`).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from pve_winrepair.domain.envelope import GuestProtocolError

if TYPE_CHECKING:
    from pve_winrepair.domain.guest_answers import BuildAnswer

__all__ = ["BuildPair", "GuestBuild", "ReceiptError", "RepairReceipt"]

_Count = Annotated[int, Field(ge=0)]
# CurrentBuild is a registry string; the drivers compare it as a number. ASCII digits only, bounded
# so int() never meets a huge or non-ASCII numeral.
_BUILD_NUMBER = re.compile(r"[0-9]{1,9}")


class BuildPair(NamedTuple):
    """A build as CurrentBuild and UBR; serialised as the JSON array ``[build, ubr]``.

    Example:
        >>> BuildPair(build=26200, ubr=7462) == (26200, 7462)
        True
    """

    build: int
    ubr: int


class GuestBuild(BaseModel):
    """The build a guest runs and when its Windows was installed, as the guest tool's ``build`` reports them.

    Attributes:
        build: CurrentBuild.
        ubr: The update build revision (UBR).
        install_date: InstallDate, Unix epoch seconds. An in-place upgrade writes it anew.

    Example:
        >>> GuestBuild(build=26200, ubr=8973, install_date=1761206400).text
        '26200.8973'
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    build: int
    ubr: int
    install_date: int

    @classmethod
    def from_answer(cls, answer: BuildAnswer) -> GuestBuild:
        """The build ``answer`` reports, with CurrentBuild read as a number.

        Raises:
            GuestProtocolError: CurrentBuild is not a number.
        """
        current = answer.current_build
        if not _BUILD_NUMBER.fullmatch(current):
            raise GuestProtocolError(f"build: CurrentBuild {current!r} is not a number")
        return cls(build=int(current), ubr=answer.ubr, install_date=answer.install_date)

    @property
    def text(self) -> str:
        """The build as ``<CurrentBuild>.<UBR>``."""
        return f"{self.build}.{self.ubr}"

    @property
    def pair(self) -> BuildPair:
        """CurrentBuild and UBR, as a receipt's ``build_before`` holds them."""
        return BuildPair(build=self.build, ubr=self.ubr)


class ReceiptError(Exception):
    """A receipt could not be written, read, validated or removed; the message names the file.

    Defined with the model rather than in the file adapter: the use cases catch it, and they may
    import the domain but never an adapter.
    """


class RepairReceipt(BaseModel):
    """What a repair's prepare step measured: the build the staged image installs, and the guest before it.

    Every field is required: a receipt without one is not valid, and apply refuses it.

    Attributes:
        vmid: The guest the repair ran on.
        image_build: The image's build number (the guest's CurrentBuild after the apply).
        image_spbuild: The image's servicing build (the guest's UBR after the apply).
        build_before: The guest's CurrentBuild and UBR when the repair measured the image.
        install_date_before: The guest's InstallDate (Unix epoch seconds) at that moment.
        written_at: When the repair wrote the receipt (UTC).

    Example:
        >>> from datetime import datetime, timezone
        >>> at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        >>> receipt = RepairReceipt(
        ...     vmid=100,
        ...     image_build=26200,
        ...     image_spbuild=8973,
        ...     build_before=(26200, 7462),
        ...     install_date_before=1761206400,
        ...     written_at=at,
        ... )
        >>> receipt.expected_build(), receipt.same_build()
        ('26200.8973', False)
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    vmid: int = Field(ge=1)
    image_build: int = Field(ge=0)
    image_spbuild: int = Field(ge=0)
    build_before: tuple[_Count, _Count]
    install_date_before: int = Field(ge=0)
    written_at: datetime

    def expected_build(self) -> str:
        """The build apply must find on the guest, as ``<CurrentBuild>.<UBR>``."""
        return f"{self.image_build}.{self.image_spbuild}"

    def same_build(self) -> bool:
        """The media carry the build the guest already ran, so the build alone cannot prove the upgrade applied."""
        return (self.image_build, self.image_spbuild) == self.build_before
