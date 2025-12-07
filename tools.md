---
layout: default
title: "Tools"
permalink: /tools/
---

# Tools

<ul>
  {% for post in site.tools %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <small> — {{ post.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>
