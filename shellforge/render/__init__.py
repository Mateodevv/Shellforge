# shellforge/render/__init__.py
"""One renderer per kind of evidence.

They are dumb on purpose. A renderer turns a list of already-decided objects
into the bytes a server would have written; it makes no decisions about the
incident. Everything that decides -- who attacked, when, what landed where --
happens in the scenario, so that the same narrative can be rendered as Apache
or Nginx, gzipped or not, without the story changing.
"""
