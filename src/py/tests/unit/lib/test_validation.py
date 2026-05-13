import pytest

from app.lib import validation
from app.lib.validation import (
    PasswordValidationError,
    ValidationError,
    validate_email,
    validate_email_format,
    validate_length,
    validate_name,
    validate_no_control_chars,
    validate_not_empty,
    validate_password,
    validate_password_strength,
    validate_phone,
    validate_slug,
    validate_url,
    validate_username,
)


class TestEnsureStr:
    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_email(123)  # type: ignore[arg-type]

    def test_password_non_string_raises(self) -> None:
        with pytest.raises(PasswordValidationError, match="must be a string"):
            validate_password_strength(42)  # type: ignore[arg-type]


class TestValidateNotEmpty:
    def test_strips_whitespace(self) -> None:
        assert validate_not_empty("  test  ") == "test"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="Value cannot be empty"):
            validate_not_empty("   ")


class TestValidateLength:
    def test_valid(self) -> None:
        assert validate_length("abc", min_length=2, max_length=5) == "abc"

    def test_too_short(self) -> None:
        with pytest.raises(ValidationError, match="Must be at least 5 characters"):
            validate_length("abc", min_length=5)

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="Must not exceed 2 characters"):
            validate_length("abc", max_length=2)


class TestValidateNoControlChars:
    def test_allows_newlines_tabs(self) -> None:
        assert validate_no_control_chars("hello\nworld\ttab\r") == "hello\nworld\ttab\r"

    def test_rejects_null_byte(self) -> None:
        with pytest.raises(ValidationError, match="Contains invalid control characters"):
            validate_no_control_chars("hello\x00world")

    def test_rejects_bell(self) -> None:
        with pytest.raises(ValidationError, match="Contains invalid control characters"):
            validate_no_control_chars("hello\x07world")


class TestValidatePasswordStrength:
    def test_valid_strong_password(self) -> None:
        validate_password_strength("StrongPass123!")

    def test_too_short(self) -> None:
        with pytest.raises(PasswordValidationError, match="at least 12 characters"):
            validate_password_strength("Short1!")

    def test_too_long(self) -> None:
        with pytest.raises(PasswordValidationError, match="must not exceed 128"):
            validate_password_strength("A" * 129 + "a1!")

    def test_no_uppercase(self) -> None:
        with pytest.raises(PasswordValidationError, match="uppercase letter"):
            validate_password_strength("weakpassword1!")

    def test_no_lowercase(self) -> None:
        with pytest.raises(PasswordValidationError, match="lowercase letter"):
            validate_password_strength("ALLUPPERCASE1!")

    def test_no_digit(self) -> None:
        with pytest.raises(PasswordValidationError, match="one digit"):
            validate_password_strength("NoDigitsPass!!")

    def test_no_special(self) -> None:
        with pytest.raises(PasswordValidationError, match="special character"):
            validate_password_strength("NoSpecialPass123")

    def test_common_password_rejected(self) -> None:
        with pytest.raises(PasswordValidationError, match="too common"):
            validate_password_strength("123456789xA!")


class TestIsCommonPassword:
    def test_exact_match(self) -> None:
        from app.lib.validation import _is_common_password

        assert _is_common_password("password") is True
        assert _is_common_password("password123") is True
        assert _is_common_password("qwertyuiop") is True

    def test_simple_repeated(self) -> None:
        from app.lib.validation import _is_common_password

        assert _is_common_password("aaaaaaaaaaaa") is True

    def test_sequential_start(self) -> None:
        from app.lib.validation import _is_common_password

        assert _is_common_password("123abcdef") is True

    def test_keyboard_start(self) -> None:
        from app.lib.validation import _is_common_password

        assert _is_common_password("qwertyfoo") is True
        assert _is_common_password("asdbar") is True

    def test_not_common(self) -> None:
        from app.lib.validation import _is_common_password

        assert _is_common_password("xK9!mNqR2vLw") is False


class TestGetPasswordStrength:
    def test_strong(self) -> None:
        result = validation.get_password_strength("Str0ngP@ss!234xx")
        assert result["strength"] == "strong"
        assert result["score"] >= 7

    def test_medium(self) -> None:
        result = validation.get_password_strength("Medium12345!")
        assert result["strength"] in ("medium", "strong")
        assert result["score"] >= 5

    def test_weak(self) -> None:
        result = validation.get_password_strength("weak")
        assert result["strength"] == "weak"
        assert result["score"] < 5

    def test_feedback_populated(self) -> None:
        result = validation.get_password_strength("short")
        assert len(result["feedback"]) > 0
        assert any("12 characters" in f for f in result["feedback"])

    def test_very_strong_bonus(self) -> None:
        result = validation.get_password_strength("VeryStr0ng!P@ssword!!!")
        assert result["score"] >= 9


class TestValidateEmail:
    def test_valid(self) -> None:
        assert validate_email("valid@example.com") == "valid@example.com"

    def test_normalizes_case(self) -> None:
        assert validate_email("VALID@EXAMPLE.COM") == "valid@example.com"

    def test_invalid_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email format"):
            validate_email("invalid-email")

    def test_blocked_domain(self) -> None:
        with pytest.raises(ValidationError, match="domain not allowed"):
            validate_email("test@10minutemail.com")

    def test_double_dot(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email format"):
            validate_email("user..name@example.com")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="too long"):
            validate_email("a" * 250 + "@b.co")

    def test_too_short(self) -> None:
        with pytest.raises(ValidationError, match="too short"):
            validate_email("a@")

    def test_blocked_pattern_test_prefix(self) -> None:
        with pytest.raises(ValidationError, match="format not allowed"):
            validate_email("testuser@example.com")

    def test_blocked_pattern_noreply(self) -> None:
        with pytest.raises(ValidationError, match="format not allowed"):
            validate_email("noreply@example.com")

    def test_blocked_pattern_spam_plus(self) -> None:
        with pytest.raises(ValidationError, match="format not allowed"):
            validate_email("user+spam@example.com")

    def test_long_local_part(self) -> None:
        with pytest.raises(ValidationError, match="local part too long"):
            validate_email("a" * 65 + "@example.com")

    def test_blocked_yopmail(self) -> None:
        with pytest.raises(ValidationError, match="domain not allowed"):
            validate_email("user@yopmail.com")


class TestValidateEmailFormat:
    def test_valid(self) -> None:
        assert validate_email_format("user@example.com") == "user@example.com"

    def test_normalizes_case(self) -> None:
        assert validate_email_format("USER@EXAMPLE.COM") == "user@example.com"

    def test_allows_blocked_domains(self) -> None:
        result = validate_email_format("user@10minutemail.com")
        assert result == "user@10minutemail.com"

    def test_allows_test_prefix(self) -> None:
        result = validate_email_format("testuser@example.com")
        assert result == "testuser@example.com"

    def test_rejects_invalid_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email format"):
            validate_email_format("not-an-email")

    def test_rejects_double_dot(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email format"):
            validate_email_format("user..name@example.com")

    def test_rejects_too_long(self) -> None:
        with pytest.raises(ValidationError, match="too long"):
            validate_email_format("a" * 250 + "@b.co")

    def test_rejects_too_short(self) -> None:
        with pytest.raises(ValidationError, match="too short"):
            validate_email_format("a@")

    def test_rejects_long_local_part(self) -> None:
        with pytest.raises(ValidationError, match="local part too long"):
            validate_email_format("a" * 65 + "@example.com")


class TestValidatePassword:
    def test_valid(self) -> None:
        result = validate_password("SecureP@ss123!")
        assert result == "SecureP@ss123!"

    def test_rejects_hash_matched_common(self) -> None:
        with pytest.raises((ValidationError, PasswordValidationError)):
            validate_password("password")

    def test_non_string_raises(self) -> None:
        with pytest.raises((ValidationError, PasswordValidationError)):
            validate_password(None)  # type: ignore[arg-type]


class TestValidateName:
    def test_basic_name(self) -> None:
        assert validate_name("John Doe") == "John Doe"

    def test_strips_and_normalizes_whitespace(self) -> None:
        assert validate_name("  Jane   Doe  ") == "Jane Doe"

    def test_international_name(self) -> None:
        assert validate_name("José García") == "José García"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_name("   ")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="must not exceed 100"):
            validate_name("A" * 101)

    def test_invalid_characters(self) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_name("John<script>")

    def test_repeated_chars(self) -> None:
        with pytest.raises(ValidationError, match="suspicious patterns"):
            validate_name("Aaaaaa")

    def test_hyphenated_name(self) -> None:
        assert validate_name("Mary-Jane") == "Mary-Jane"

    def test_apostrophe_name(self) -> None:
        assert validate_name("O'Brien") == "O'Brien"

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_name(42)  # type: ignore[arg-type]


class TestValidateUsername:
    def test_valid(self) -> None:
        assert validate_username("johndoe") == "johndoe"

    def test_normalizes_case(self) -> None:
        assert validate_username("JohnDoe") == "johndoe"

    def test_allows_hyphens_underscores(self) -> None:
        assert validate_username("john-doe_99") == "john-doe_99"

    def test_too_short(self) -> None:
        with pytest.raises(ValidationError, match="at least 3 characters"):
            validate_username("ab")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="must not exceed 30"):
            validate_username("a" * 31)

    def test_invalid_characters(self) -> None:
        with pytest.raises(ValidationError, match="can only contain"):
            validate_username("user@name")

    def test_must_start_with_alphanumeric(self) -> None:
        with pytest.raises(ValidationError, match="must start with"):
            validate_username("-username")

    def test_reserved_username(self) -> None:
        with pytest.raises(ValidationError, match="reserved"):
            validate_username("admin")

    def test_reserved_root(self) -> None:
        with pytest.raises(ValidationError, match="reserved"):
            validate_username("root")

    def test_repeated_chars(self) -> None:
        with pytest.raises(ValidationError, match="too many repeated"):
            validate_username("aaaa_user")

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_username(123)  # type: ignore[arg-type]


class TestValidateUrl:
    def test_valid_https(self) -> None:
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http(self) -> None:
        assert validate_url("http://example.com/path") == "http://example.com/path"

    def test_strips_whitespace(self) -> None:
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="URL too long"):
            validate_url("https://example.com/" + "a" * 2050)

    def test_missing_scheme(self) -> None:
        with pytest.raises(ValidationError, match="must include a scheme"):
            validate_url("example.com")

    def test_invalid_scheme(self) -> None:
        with pytest.raises(ValidationError, match="scheme must be"):
            validate_url("ftp://example.com")

    def test_missing_hostname(self) -> None:
        with pytest.raises(ValidationError, match="must include a hostname"):
            validate_url("https://")

    def test_blocked_localhost(self) -> None:
        with pytest.raises(ValidationError, match="domain not allowed"):
            validate_url("https://localhost/path")

    def test_blocked_127(self) -> None:
        with pytest.raises(ValidationError, match="domain not allowed"):
            validate_url("https://127.0.0.1/path")

    def test_suspicious_javascript(self) -> None:
        with pytest.raises(ValidationError, match="suspicious content"):
            validate_url("https://example.com/javascript:alert(1)")

    def test_suspicious_data(self) -> None:
        with pytest.raises(ValidationError, match="suspicious content"):
            validate_url("https://example.com/data:text/html")

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_url(42)  # type: ignore[arg-type]


class TestValidateSlug:
    def test_valid(self) -> None:
        assert validate_slug("my-slug") == "my-slug"

    def test_normalizes_case(self) -> None:
        assert validate_slug("My-Slug") == "my-slug"

    def test_alphanumeric(self) -> None:
        assert validate_slug("slug123") == "slug123"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_slug("   ")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="must not exceed 100"):
            validate_slug("a" * 101)

    def test_invalid_characters(self) -> None:
        with pytest.raises(ValidationError, match="can only contain"):
            validate_slug("my_slug")

    def test_leading_hyphen(self) -> None:
        with pytest.raises(ValidationError, match="cannot start or end with"):
            validate_slug("-slug")

    def test_trailing_hyphen(self) -> None:
        with pytest.raises(ValidationError, match="cannot start or end with"):
            validate_slug("slug-")

    def test_consecutive_hyphens(self) -> None:
        with pytest.raises(ValidationError, match="cannot contain consecutive"):
            validate_slug("my--slug")

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_slug(42)  # type: ignore[arg-type]


class TestValidatePhone:
    def test_valid_us(self) -> None:
        assert validate_phone("+1 (555) 123-4567") == "+1 (555) 123-4567"

    def test_valid_international(self) -> None:
        assert validate_phone("+44 20 7946 0958") == "+44 20 7946 0958"

    def test_strips_whitespace(self) -> None:
        assert validate_phone("  +15551234567  ") == "+15551234567"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_phone("   ")

    def test_invalid_characters(self) -> None:
        with pytest.raises(ValidationError, match="Invalid phone number format"):
            validate_phone("+1-555-ABC-1234")

    def test_too_few_digits(self) -> None:
        with pytest.raises(ValidationError, match="between 7 and 15"):
            validate_phone("12345")

    def test_too_many_digits(self) -> None:
        with pytest.raises(ValidationError, match="between 7 and 15"):
            validate_phone("1234567890123456")

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_phone(5551234567)  # type: ignore[arg-type]
