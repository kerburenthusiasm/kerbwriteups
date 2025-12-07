---
layout: page
title: Others
permalink: /others/
---

# Others

<ul>
  {% for p in site.others %}
    <li>
      <a href="{{ p.url | relative_url }}">{{ p.title }}</a>
      <small> — {{ p.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>
