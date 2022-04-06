# Publishing the documentation

The tool used to generate the HTML pages is [mkdocs](https://www.mkdocs.org).

## Adding documents to the navigation menu

While all documents in the git tree are published, they need to be
manually added to the navigation menu.

To do this, add it to the appropriate subsection under the `nav:` section
of `/doc/mkdocs.yml`.

## Testing changes locally

You'll need to install mkdocs, the theme we use and plugins. You'll need to have
Python3 installed.

```
pip3 install mkdocs mkdocs-material
```

Run the following command to build the documentation:

```
ninja doc-html
```

You can now open `/doc-html/index.html` in your web browser and continue browsing from there.

## Relative vs. absolute links

Due to the way `mkdocs` works, all links in the documentation need to be relative
and not absolute.

**Example**: Don't link to `/src/univalue/README.md` but do link to `../src/univalue/README.md`,
if the document you are linking *from* is in the `/doc/` folder.
