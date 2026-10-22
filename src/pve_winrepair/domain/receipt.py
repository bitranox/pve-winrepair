"""The repair receipt: the image build a repair's prepare step measured, for apply to verify against.

The build an in-place repair installs is the build of the WIM image it stages, which only the
guest can read (``prepare`` reports it). A repair records it in a receipt per VM; apply reads that
receipt before it touches the guest and refuses without one, so the build it verifies is always
the one this VM's media carried, never a constant that holds for one media release only.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ReceiptError", "RepairReceipt"]


class ReceiptError(Exception):
    """A receipt could not be written, read, validated or removed; the message names the file.

    Defined with the model rather than in the file adapter: the use cases catch it, and they may
    import the domain but never an adapter.
    """


class RepairReceipt(BaseModel):
    """What a repair's prepare step measured: the build the staged image installs.

    Attributes:
        vmid: The guest the repair ran on.
        image_build: The image's build number (the guest's CurrentBuild after the apply).
        image_spbuild: The image's servicing build (the guest's UBR after the apply).
        written_at: When the repair wrote the receipt (UTC).

    Example:
        >>> from datetime import datetime, timezone
        >>> at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        >>> RepairReceipt(vmid=100, image_build=26200, image_spbuild=8973, written_at=at).expected_build()
        '26200.8973'
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    vmid: int = Field(ge=1)
    image_build: int = Field(ge=0)
    image_spbuild: int = Field(ge=0)
    written_at: datetime

    def expected_build(self) -> str:
        """The build apply must find on the guest, as ``<CurrentBuild>.<UBR>``."""
        return f"{self.image_build}.{self.image_spbuild}"
