GUI drafts for ttproto
======================

Author Andriamilanto Tompoariniaina (tompo.andri@gmail.com)

Those files are some drafts for testing ttproto's API and design research for
a GUI that should have been integrated to the F-Interop project. Some parts are
integrated into the coordinator's GUI.

Frameworks used
---------------
I used different frameworks for client side, here is a little list of them:

- [Jquery](https://jquery.com):
    JavaScript framework for faster and easier development
- [Boostrap](http://getbootstrap.com):
    Design framework that allows you to build pretty GUI
- [React](https://facebook.github.io/react/index.html):
    JavaScript framework providing dynamic webpages
- [Browser](https://cdnjs.com/libraries/babel-core/5.8.34):
    Bable on the fly compiler to allow us to put Babel code into JavaScript

All of them are **loaded from CDNs** for it to be simpler and for us not having
to manage this.


How to execute
--------------
You simply have to run a simple Python webserver into the drafts directory:

```
python -m SimpleHTTPServer 8000
```

Then access the webserver from your browser putting **http://127.0.0.1:8000**
as url. Then you will see the list of html files, the purpose of each one is
described bellow.

> **NOTE**
>
> The GUI's are per default plugged onto **CoAP** TAT on **port 2080**, every
> file described bellow will indicate you how to plug it onto another TAT.

You may have **errors or no response** at all because every **web browsers now
block cross-origin requests** because you are executing the GUI's webserver on
port 8000 and the **TAT API** on which we will execute requests is ran on
another port.

The solution is to configure your browser to stop blocking those requests or
install a plugin that will allow them for a brief moment. For my part I'm using
**Chrome** with the [**Allow-Control-Allow-Origin:\* **](https://chrome.google.com/webstore/detail/allow-control-allow-origi/nlfbmbojpeacfghkpbjhddihlkkiljbi?hl=en-US) plugin.

After installing it, you will have a **little box at the upper right** of your
browser and when clicking on it, you will see a radio button saying *Enable
cross-origin ressource sharing* and you can active it the time you are using the
GUIs, **don't forget to deactivate it** afterward.

> **WARNING**
>
> Allowing cross-origin requests can lead to **security problems**, use this
> tool with caution, never forget to deactivate it and when activating it, only
> browse on the GUI pages.


Test post analyze and dissect
-----------------------------
The two files named **post_test_dissect.html** and **post_test_analyze.html**
can be used to test respectively the dissection and analysis using a TAT's API.
The result will be a simple page displaying the Json, no processing is done on
the data.

You can change the TAT address or url used by editing **line 62**.

#### post_test_dissect
To use this page, you just have to provide a **pcap file** and optionnaly a
**protocol name**.

#### post_test_analyze
To use this page, you just have to provide a **pcap file** and the **id of the
test case**.


The two design research files
-----------------------------
The two files named **web-gui.html** and **web-gui-frames.html** are just design
researches files and actions are not binded into them. I let them because this
is what I used afterward for coordinator's GUI and it's easier to read them than
the dynamically generated HTML from coordiantor's GUI.


Web gui using React
-------------------
This GUI is the one that is the most advanced and contains a functionnal code
using React framework. This can be reused later into the F-Interop project and
inspired the JavaScript code for the coordinator's GUI.

You can change the TAT address or url used by editing **line 4**.

To use it, you have to provide a **pcap file** and then choose the action to be
executed, **analyze** or **dissect** and at the end, you choose between the
options that are provided in the list. Testcase id for analysis and protocol for
dissection.

This GUI's isn't fully working because I let it aside during development to work
on coordinator's GUI, but both are very similar, the main difference is that
coordinator's GUI doesn't use React.
