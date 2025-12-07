---
layout: default
title: "CTF Writeups"
permalink: /ctf/
---

# CTF Writeups

## HTB
<ul>
  {% for post in site.ctf %}
    {% if post.platform == "htb" %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a>
        <small> — {{ post.date | date: "%Y-%m-%d" }}</small>
      </li>
    {% endif %}
  {% endfor %}
</ul>

## Other Platforms
<ul>
  {% assign other_ctf = site.ctf | where_exp: "post", "post.platform != 'htb'" %}
  {% for post in other_ctf %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <small> — {{ post.date | date: "%Y-%m-%d" }} ({{ post.platform | upcase }})</small>
    </li>
  {% endfor %}
</ul>
