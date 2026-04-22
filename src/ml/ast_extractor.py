"""
Tree-sitter AST Parser — Stream B, Semantic Analysis
Builds AST and extracts CFG-style paths for prompt construction.
Architecture: Source Code → Tree-sitter → CFG paths → Prompt Builder
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Map PatchScout language names → tree-sitter language identifiers
_LANG_MAP = {
    'python':     'python',
    'java':       'java',
    'c':          'c',
    'cpp':        'cpp',
    'c++':        'cpp',
    'javascript': 'javascript',
    'js':         'javascript',
    'php':        'php',
}

# Node types that mark interesting control/data-flow points in the AST
_INTERESTING = {
    'function_definition', 'function_declaration',
    'method_declaration',  'method_definition',
    'if_statement',
    'for_statement',       'for_in_statement',    'enhanced_for_statement',
    'while_statement',
    'call_expression',     'method_invocation',   'function_call',
    'argument_list',       'arguments',
    'parameter',           'formal_parameter',
    'return_statement',
    'assignment_expression', 'assignment',
    'binary_expression',
}

try:
    from tree_sitter_languages import get_parser as _ts_get_parser
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False
    logger.warning(
        "tree-sitter-languages not installed — AST extraction will use regex fallback. "
        "Run: pip install tree-sitter-languages"
    )


class ASTExtractor:
    """
    Extracts AST-derived CFG paths from source code.

    Usage:
        extractor = ASTExtractor()
        result = extractor.extract(code, 'python')
        # result['paths'] → List[str] e.g. ['param(user_id) → if_stmt → call_expr(execute)']
    """

    def __init__(self):
        self.available = _TS_AVAILABLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, code: str, language: str) -> Dict:
        """
        Parse code and return CFG paths + function names.

        Returns:
            {
                'paths':      List[str],   # up to 10 CFG path strings
                'functions':  List[str],   # function/method names found
                'available':  bool,        # whether tree-sitter was used
                'node_count': int,
            }
        """
        lang_key = _LANG_MAP.get(language.lower(), language.lower())

        if self.available:
            try:
                return self._ts_extract(code, lang_key)
            except Exception as e:
                logger.debug(f"tree-sitter failed ({lang_key}): {e} — using regex fallback")

        return self._regex_extract(code, language)

    # ------------------------------------------------------------------
    # Tree-sitter extraction
    # ------------------------------------------------------------------

    def _ts_extract(self, code: str, lang_key: str) -> Dict:
        parser = _ts_get_parser(lang_key)
        tree   = parser.parse(code.encode('utf-8', errors='replace'))
        root   = tree.root_node

        functions  = self._collect_function_names(root, code)
        paths      = self._collect_paths(root, code)
        node_count = self._count_nodes(root)

        return {
            'paths':      paths[:10],
            'functions':  functions[:20],
            'available':  True,
            'node_count': node_count,
        }

    def _collect_function_names(self, root, code: str) -> List[str]:
        func_types = {
            'function_definition', 'function_declaration',
            'method_declaration',  'method_definition',
        }
        names: List[str] = []
        self._walk(root, lambda n: self._grab_name(n, code, names), func_types)
        return names

    def _grab_name(self, node, code: str, out: List[str]):
        """Collect the identifier child of a function/method node."""
        for child in node.children:
            if child.type == 'identifier':
                out.append(code[child.start_byte:child.end_byte])
                break

    def _collect_paths(self, root, code: str) -> List[str]:
        """
        DFS traversal building CFG paths.
        Each path is ' → '-joined labels like:
            param(user_id) → if_stmt → call_expr(execute)
        """
        raw_paths: List[str] = []
        self._dfs_paths(root, code, [], raw_paths, max_depth=8)

        # Deduplicate, filter trivial single-label paths
        seen:   set        = set()
        result: List[str]  = []
        for p in raw_paths:
            if p not in seen and ' → ' in p:
                seen.add(p)
                result.append(p)
            if len(result) >= 30:
                break
        return result

    def _dfs_paths(
        self,
        node,
        code: str,
        current: List[str],
        out: List[str],
        max_depth: int,
    ):
        if max_depth == 0 or len(out) >= 60:
            return

        label = self._node_label(node, code)
        if label:
            current = current + [label]
            if len(current) >= 2:
                out.append(' → '.join(current))

        for child in node.children:
            # Skip comment nodes — they add noise
            if child.type in ('comment', 'line_comment', 'block_comment'):
                continue
            self._dfs_paths(child, code, current, out, max_depth - 1)

    def _node_label(self, node, code: str) -> Optional[str]:
        """Return a readable short label for interesting node types, None otherwise."""
        t = node.type

        if t in ('function_definition', 'function_declaration',
                  'method_declaration',  'method_definition'):
            return 'func_def'

        if t == 'if_statement':
            return 'if_stmt'

        if t in ('for_statement', 'for_in_statement', 'enhanced_for_statement'):
            return 'for_loop'

        if t == 'while_statement':
            return 'while_loop'

        if t in ('call_expression', 'method_invocation', 'function_call'):
            for child in node.children:
                if child.type == 'identifier':
                    name = code[child.start_byte:child.end_byte]
                    return f'call_expr({name})'
            return 'call_expr'

        if t in ('parameter', 'formal_parameter'):
            for child in node.children:
                if child.type == 'identifier':
                    name = code[child.start_byte:child.end_byte]
                    return f'param({name})'
            return 'param'

        if t == 'return_statement':
            return 'return'

        if t in ('assignment_expression', 'assignment'):
            return 'assign'

        if t == 'binary_expression':
            return 'binary_expr'

        return None

    def _walk(self, node, callback, filter_types: Optional[set] = None):
        if filter_types is None or node.type in filter_types:
            callback(node)
        for child in node.children:
            self._walk(child, callback, filter_types)

    def _count_nodes(self, root) -> int:
        total = [0]

        def inc(n):
            total[0] += 1

        self._walk(root, inc)
        return total[0]

    # ------------------------------------------------------------------
    # Regex fallback (no tree-sitter)
    # ------------------------------------------------------------------

    def _regex_extract(self, code: str, language: str) -> Dict:
        """Simple line-level regex fallback when tree-sitter is unavailable."""
        lines   = code.splitlines()
        paths:     List[str] = []
        functions: List[str] = []

        func_re = re.compile(
            r'\b(?:def|function|void|int|str|bool|public|private|protected|static)\s+(\w+)\s*\('
        )
        call_re = re.compile(r'\b(\w+)\s*\(')
        if_re   = re.compile(r'^\s*if\b')
        for_re  = re.compile(r'^\s*for\b')
        while_re = re.compile(r'^\s*while\b')

        for line in lines[:200]:
            m = func_re.search(line)
            if m:
                functions.append(m.group(1))

        for line in lines[:200]:
            parts: List[str] = []
            if if_re.search(line):
                parts.append('if_stmt')
            elif for_re.search(line):
                parts.append('for_loop')
            elif while_re.search(line):
                parts.append('while_loop')

            calls = call_re.findall(line)
            for c in calls[:2]:
                if c not in ('if', 'for', 'while', 'return', 'def', 'class'):
                    parts.append(f'call_expr({c})')

            if len(parts) >= 2:
                paths.append(' → '.join(parts))
            if len(paths) >= 20:
                break

        return {
            'paths':      paths[:10],
            'functions':  functions[:20],
            'available':  False,
            'node_count': 0,
        }
