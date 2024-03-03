+++
title = 'My first steps in MalDev'
date = 2024-02-28T20:53:30+01:00
draft = false
showDate = true
description = 'Aweonao'
toc = true
+++
## Prelude
Around this last month I have been digging into the Malware Development world. I have always wanted to expand my knowledge within this field, and I felt like it was the moment to do so. 

As mentioned in many other blogposts, [Sektor7 Malware Development Essentials](https://www.google.com/search?client=firefox-b-d&q=sektor7+malware+development) course was a good point to start. Nevertheless, I found this course very short and I felt like most of the important concepts are ignored (e.g., **what is a handle?**) and are just used like if I already know them.

Because of that, I actually recommend **take a little stop on each of the things that the course shows you in order to UNDERSTAND what does each line do** and also do some personal research on each of the things that the course provides.

I personally made questions like:
- What are the parameters of this function? 
- Why is this function called in the code?
- How could I develop this in a way that it could be more stealthy?
- What are these compile options?

I wanted to make sure that I really learnt from this course and compiling and execute the code they give you is not the way to do it. I personally recommend to watch their videos, take some notes, and reproduce and execute the code in your personal project files. **Do not be scared to improve or modify the code they give you if you think that can be useful.**

The result of following these steps was a final course project in which I included all of the techniques given in the course to avoid detection (mainly static detection, it is a basic course) **combined with am extra technique that made me bypass Windows Defender sandbox analysis.**

Please note that I have just started to learn about these things and that I can be wrong; feel free to contact me at any of my social media 

##  ¿Evasive? dropper

### 2nd level parrafo