---
layout: page
title: CTF Writeups
permalink: /ctf/
---

# CTF Writeups

<ul>
  {% for c in site.ctfs %}
    <li>
      <a href="{{ c.url | relative_url }}">{{ c.title }}</a>
      <small> — {{ c.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>
