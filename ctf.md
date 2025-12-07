---
layout: default
title: "CTF Writeups"
permalink: /ctf/
---

# CTF Writeups

## HTB

<ul>
  {% for c in site.ctfs %}
    {% if c.platform == "htb" %}
      <li>
        <a href="{{ c.url | relative_url }}">{{ c.title }}</a>
        <small> — {{ c.date | date: "%Y-%m-%d" }}</small>
      </li>
    {% endif %}
  {% endfor %}
</ul>

{% assign other_ctf = site.ctfs | where_exp: "c", "c.platform != 'htb'" %}
{% if other_ctf.size > 0 %}
## Other Platforms

<ul>
  {% for c in other_ctf %}
    <li>
      <a href="{{ c.url | relative_url }}">{{ c.title }}</a>
      <small> — {{ c.date | date: "%Y-%m-%d" }} ({{ c.platform | upcase }})</small>
    </li>
  {% endfor %}
</ul>
{% endif %}
