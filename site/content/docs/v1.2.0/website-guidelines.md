---
title: "Website Guidelines"
layout: docs
---

## Running the website locally

When making changes to the website, please run the site locally before submitting a PR and manually verify your changes.

At the root of the project, run:

```bash
make serve-docs
```

This runs all the Ruby dependencies in a container.

Alternatively, for quickly loading the website, under the `velero/site/` directory run:

```bash
bundle exec jekyll serve --livereload --future
```

For more information on how to run the website locally, please see our [jekyll documentation](https://github.com/velero-io/velero/blob/v1.2.0/site/README-JEKYLL.md).

## Adding a blog post

The `author_name` value must also be included in the tags field so the page that lists the author's posts will work properly (Ex: https://velero.io/tags/carlisia%20campos/). 

Note that the tags field can have multiple values. 

Example:

```text
author_name: Carlisia Campos
tags: ['Carlisia Campos', "release", "how-to"]
```

### Please add an image

If there is no image added to the header of the post, the default Velero logo will be used. This is fine, but not ideal. 

If there's an image that can be used as the blog post icon, the image field must be set to: 

```text
image: /img/posts/<your_image_name.png>
```

This image file must be added to the `/site/img/posts` folder.
