---
layout: default
title: "Others"
permalink: /others/
---

# Others

<ul>
  {% for post in site.others %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <small> — {{ post.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>
