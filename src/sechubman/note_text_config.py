"""Domain model for note text configuration."""

from dataclasses import dataclass

NOTE_TEXT_CONFIG_MODE_VALUES = {"plaintext", "jsonUpdate"}


@dataclass
class NoteTextConfig:
    """Configuration for note text handling.

    Raises
    ------
    ValueError
        If the Mode is not one of the allowed values.
    ValueError
        If the Key is not a string when Mode is 'jsonUpdate'.
    ValueError
        If the Key is set when Mode is 'plaintext'.
    """

    Mode: str
    Key: str = ""

    def __post_init__(self) -> None:
        """Validate the NoteTextConfig upon initialization."""
        if self.Mode not in NOTE_TEXT_CONFIG_MODE_VALUES:
            msg = (
                "'ExtraFeatures.NoteTextConfig.Mode' should be one of "
                "'plaintext' or 'jsonUpdate'"
            )
            raise ValueError(msg)

        if self.Mode == "jsonUpdate":
            if not isinstance(self.Key, str) or not self.Key:
                msg = (
                    "'ExtraFeatures.NoteTextConfig.Key' should be a non-empty string "
                    "when mode is 'jsonUpdate'"
                )
                raise ValueError(msg)
        elif self.Key:
            msg = "'ExtraFeatures.NoteTextConfig.Key' should not be set when mode is 'plaintext'"
            raise ValueError(msg)
