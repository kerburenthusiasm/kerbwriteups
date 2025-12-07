---
layout: page
title: Tools
permalink: /tools/
---

# Tools

<ul>
  {% for t in site.tools %}
    <li>
      <a href="{{ t.url | relative_url }}">{{ t.title }}</a>
      <small> — {{ t.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>
