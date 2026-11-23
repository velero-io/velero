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

This runs all the Hugo dependencies in a container.

Alternatively, for quickly loading the website, under the `velero/site/` directory run:

```bash
hugo serve
```

For more information on how to run the website locally, please see our [Hugo documentation](https://gohugo.io/getting-started/).

## Adding a blog post

To add a blog post, create a new markdown (.MD) file in the `/site/content/posts/` folder. A blog post requires the following front matter.

```yaml
title: "Title of the blog"
excerpt: Brief summary of thee blog post that appears as a preview on velero.io/blogs
author_name: Jane Smith
slug: URL-For-Blog
# Use different categories that apply to your blog. This is used to connect related blogs on the site
categories: ['velero','release']
# Image to use for blog. The path is relative to the site/static/ folder
image: /img/posts/example-image.jpg
# Tag should match author to drive author pages. Tags can have multiple values.
tags: ['Velero Team', 'Nolan Brubaker']
```

Include the `author_name` value in tags field so the page that lists the author's posts will work properly, for example https://velero.io/tags/carlisia-thompson/.

Ideally each blog will have a unique image to use on the blog home page, but if you do not include an image, the default Velero logo will be used instead. Use an image that is less than 70KB and add it to the `/site/static/img/posts` folder.
