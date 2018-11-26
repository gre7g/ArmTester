import logging
import re

from arm_tester.types import Char, Unsigned8, Unsigned16, Unsigned32, Signed8, Signed16, Signed32, ArrayOf, PointerTo, \
    Void, Boolean

NON_SPACE = re.compile(r" *(\S)")
WORD = re.compile(r"^[_a-zA-Z]\w*")
LINE_COMMENT = re.compile(r"^//.*$", re.M)
PRAGMA = re.compile(r"^#.*$", re.M)
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
NUMBER = re.compile(r"^[0-9]+")
SIMPLE_STRING = re.compile(r'^"[^"]*"')

TYPES = {"U8": Unsigned8, "U16": Unsigned16, "U32": Unsigned32,
         "S8": Signed8, "S16": Signed16, "S32": Signed32,
         "uint8_t": Unsigned8, "uint16_t": Unsigned16, "uint32_t": Unsigned32,
         "int8_t": Signed8, "int16_t": Signed16, "int32_t": Signed32,
         "char": Char, "void": Void, "bool": Boolean, "Boolean": Boolean}

LOG = logging.getLogger(__name__)

IGNORE_WORDS = ["const"]


class ProtoParser(object):
    def __init__(self, ignore_words):
        self.ignore_words = (ignore_words if ignore_words else []) + IGNORE_WORDS

    def parse(self, text):
        return_value = self.parse_argument(text, True)
        if return_value is None:
            return

        parts, chunk, text = return_value
        name = parts.pop()
        returns = self.combine_parts(parts)
        # LOG.debug("parts=%r", parts)

        assert chunk == "("

        args = []
        while True:
            return_value = self.parse_argument(text, False)
            if return_value is None:
                return

            parts, chunk, text = return_value

            if parts:
                # LOG.debug("parts=%r", parts)
                args.append(self.combine_parts(parts))
            if chunk == ")":
                break
            assert chunk == ","

        return_value = self.parse_argument(text, False)
        if return_value is None:
            return

        parts, chunk, text = return_value
        assert chunk == "{"

        return name, returns, args

    @staticmethod
    def combine_parts(parts):
        LOG.debug("combining %r", parts)
        arg = None
        while parts:
            part = parts.pop()
            if isinstance(part, str):
                assert arg is None, "too many strings"
                arg = part
            else:
                arg = part(arg)

        return arg

    def parse_argument(self, text, skip_pragma):
        parts = []

        while True:
            return_value = self.parse_line_chunk(text, skip_pragma)
            if return_value is None:
                return

            classifier, chunk, text = return_value

            if classifier == "CR":
                skip_pragma = True
                continue
            else:
                skip_pragma = False

            if classifier == "WORD":
                if chunk in TYPES:
                    parts.append(TYPES[chunk])
                elif chunk == "__attribute__":
                    text = self.skip_attribute(text)
                    skip_pragma = False
                elif chunk not in (self.ignore_words):
                    parts.append(chunk)

            elif classifier == "NUMBER":
                assert False, "parse number"

            else:
                if chunk == "*":
                    parts.insert(-1, PointerTo)
                elif chunk in ["(", ")", ",", "{"]:
                    return parts, chunk, text
                else:
                    assert False, ("wasn't ready for %r" % chunk)

    def skip_attribute(self, text):
        skip_pragma = False

        while True:
            return_value = self.parse_line_chunk(text, skip_pragma)
            if return_value is None:
                assert False, "expecting ("

            classifier, chunk, text = return_value

            if classifier == "CR":
                skip_pragma = True
                continue
            else:
                skip_pragma = False

            assert chunk == "("
            break

        parens = 1

        while True:
            return_value = self.parse_line_chunk(text, skip_pragma)
            if return_value is None:
                assert False, "expecting )"

            classifier, chunk, text = return_value

            if classifier == "CR":
                skip_pragma = True
                continue
            else:
                skip_pragma = False

            if chunk == "(":
                parens += 1
            elif chunk == ")":
                parens -= 1
                if parens == 0:
                    return text
            elif chunk == '"':
                match = SIMPLE_STRING.search(text)
                assert match, "expected string to end"
                text = text[match.end(0)]

    def parse_line_chunk(self, text, skip_pragmas=False):
        while True:
            # Skip whitespace
            match = NON_SPACE.search(text)
            if not match:
                return
            character = match.group(1)
            text = text[match.start(1):]

            if character == "\n":
                return "CR", character, text

            if skip_pragmas:
                match = PRAGMA.search(text)
                if match:
                    text = text[match.end(0):]
                    continue

            match = LINE_COMMENT.search(text)
            if match:
                text = text[match.end(0):]
                continue

            match = BLOCK_COMMENT.search(text)
            if match:
                text = text[match.end(0):]
                continue

            match = WORD.search(text)
            if match:
                return "WORD", match.group(0), text[match.end(0):]

            match = NUMBER.search(text)
            if match:
                return "NUMBER", match.group(0), text[match.end(0):]

            return "SYMBOL", character, text[1:]
