"""Parser-manifest JSON Schema package.

Exists so the schema directory is an importable package, which lets the JSON
Schema ship as package data and be located via importlib.resources on an
installed distribution rather than only through a source checkout.
"""
