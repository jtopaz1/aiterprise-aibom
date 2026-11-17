"""JSON5, the format of OpenClaw's config. The reader is small and strict: what it does not understand
raises ValueError, which the MCP analyzer reports as a config it could not analyse, never as a clean one."""

import unittest

from aiterprise_scan.textio import loads_json5


class Json5Tests(unittest.TestCase):
    def test_the_openclaw_documentation_example(self):
        text = """// ~/.openclaw/openclaw.json
{
  mcp: {
    servers: {
      fetch: { command: "uvx", args: ["mcp-server-fetch"], },
      remote: {
        url: 'https://example.com/mcp',
        transport: "streamable-http", // streamable-http | sse
        headers: { Authorization: "Bearer ${MCP_REMOTE_TOKEN}" },
        enabled: false,
      },
    },
  },
  /* skills */ skills: { load: { extraDirs: ["~/path/to/agent-scripts/skills"] } },
}"""
        self.assertEqual(loads_json5(text), {
            "mcp": {"servers": {
                "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                "remote": {"url": "https://example.com/mcp", "transport": "streamable-http",
                           "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"}, "enabled": False}}},
            "skills": {"load": {"extraDirs": ["~/path/to/agent-scripts/skills"]}}})

    def test_values(self):
        self.assertEqual(loads_json5("[0x1F, .5, 5., +3, -2, 1e3, Infinity, null, true, 'it\\'s', \"a\\nb\"]")[:6],
                         [31, 0.5, 5.0, 3, -2, 1000.0])
        self.assertEqual(loads_json5("['it\\'s', \"a\\nb\", 'x\\\ny', \"\\u0041\"]"), ["it's", "a\nb", "xy", "A"])
        # a backslash before any line terminator continues the string: CRLF, U+2028 and U+2029 too
        self.assertEqual(loads_json5("['a\\\r\nb', 'c\\\u2028d', 'e\\\u2029f', 'g\\ h']"), ["ab", "cd", "ef", "g h"])
        self.assertEqual(loads_json5('{"quoted": 1, $dollar_ok: 2, _x9: 3}'), {"quoted": 1, "$dollar_ok": 2, "_x9": 3})

    def test_strings_keep_what_looks_like_comments(self):
        self.assertEqual(loads_json5('{u: "http://x//y", v: "/* no */"}'), {"u": "http://x//y", "v": "/* no */"})

    def test_what_is_not_json5(self):
        for bad in ("{a: }", "{a 1}", "[1 2]", "{'a': 1", "'open", "{a: undefined}", "{a: 1} x", "",
                    "[" * 5000 + "]" * 5000):
            with self.subTest(bad=bad[:20]), self.assertRaises(ValueError):
                loads_json5(bad)


if __name__ == "__main__":
    unittest.main()
