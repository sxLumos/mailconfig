# Email Auto-configuration Test Tool

Email auto-configuration mechanisms were designed to retrieve mail server configuration information automatically, allowing users to log in their mail account by simply entering the mail address and password. Nowadays,  most of email clients (both mobile and desktop) have implemented this function.

On the server side, three commonly adopted configuration mechanisms exist, including Autodiscover ([MS-OXDISCO](https://msopenspecs.azureedge.net/files/MS-OXDISCO/%5bMS-OXDISCO%5d.pdf), [MS-OXDSCLI](https://msopenspecs.azureedge.net/files/MS-OXDSCLI/%5bMS-OXDSCLI%5d.pdf)), Autoconfig ([Draft-autoconfig](https://datatracker.ietf.org/doc/draft-bucksch-autoconfig/00/), [Wiki-Autoconfiguration](https://wiki.mozilla.org/Thunderbird:Autoconfiguration)), and SRV service discovery ([RFC 6186](https://datatracker.ietf.org/doc/html/rfc6186)/[8314](https://datatracker.ietf.org/doc/html/rfc8314)). On the client side, built-in configuration information from popular mail providers (e.g., [ISPDB](https://github.com/thunderbird/autoconfig)) is the commonly implemented mechanism.

Mailconfig is based on the above specifications or drafts and implements the retrieval of configuration information for a mail domain (also includes several commonly used built-in lists) to help administrators check for and identify lagging (out-of-date) and inconsistent configuration information.

## Installation

Create a virtual environment and install libraries:

```shell
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

```
python3 getconfig.py -a username@example.com
```

The built-in lists included in this tool (feel free to add more lists):

- [ISPDB](https://github.com/thunderbird/autoconfig), a generic database of mail server configuration.
- [Nodemailer](https://github.com/nodemailer/nodemailer/tree/d1ae0a86883ba6011a49a5bbdf076098e2e3637a), a module for Node.js applications that allows easy email sending.
- [MailCore2](https://github.com/MailCore/mailcore2/blob/7417b2e8dd7e2c028aadb72056e4d1428c0627c4/resources/providers.json), a simple and asynchronous API to work with e-mail protocols IMAP, POP and SMTP.
- [Deltachat-core-rust](https://github.com/deltachat/deltachat-core-rust/blob/137e32fe49bc51a0602b158fc9e8a0df054384d3/src/provider/data.rs), a library used by Android/iOS/desktop apps, bindings and bots.
- [FairEmail](https://github.com/M66B/FairEmail/blob/be474a7aa3dedd695d29152dca305e4c9f8b03e6/app/src/main/res/xml/providers.xml), an open source, privacy friendly email app for Android.
- [Mailspring](https://github.com/Foundry376/Mailspring/blob/17aa64165577c6bb794a13f6f2ddd19556c4ecc1/app/internal_packages/onboarding/lib/mailspring-provider-settings.json), an open source mail client for Mac, Windows and Linux.


## Note

- This tool is only designed for testing individual domains and not for large-scale scanning and analysis.
- This tool is not tested with IPv6.
- The configuration information obtained by this tool does not cover all the configurations that a user might get in a real application.
- All built-in lists (except ISPDB) were downloaded during our experiments and the current lists may be updated. For ISPDB, we issue a real-time query to retrieve the configuration information.
- For Autoconfig, the URL patterns vary across different draft versions. This tool references [draft-bucksch-autoconfig-00](https://datatracker.ietf.org/doc/draft-bucksch-autoconfig/00/).

## Previous studies

Studies related to Autodiscover for Exchange:

- [BlackHat Asia'2017 -  All your emails belong to us: exploiting vulnerable email clients via domain name collision.](https://www.blackhat.com/docs/asia-17/materials/asia-17-Nesterov-All-Your-Emails-Belong-To-Us-Exploiting-Vulnerable-Email-Clients-Via-Domain-Name-Collision-wp.pdf)
- [PoC'2017 - We can wipe your email.](https://www.powerofcommunity.net/poc2017/ilya.pdf)
- [Autodiscovering the Great Leak.](https://www.akamai.com/blog/security/autodiscovering-the-great-leak)

## Cite Our Paper

```latex
@inproceedings{emailconfig,
  author 	= {Shushang Wen and Yiming Zhang and Yuxiang Shen and Bingyu Li and Haixin Duan and Jingqiang Lin},
  title 	= {Automatic Insecurity: Exploring Email Auto-configuration in the Wild},
  booktitle = {32nd Annual Network and Distributed System Security Symposium, {NDSS}
                  2025, San Diego, California, USA, February 24 - 28, 2025},
  publisher	= {The Internet Society},
  year		= {2025}
}
```

## Furthermore

While numerous auto-configuration mechanisms exist today, there is no community consensus on which approaches to adopt, resulting in fragmented implementations across the field. The recent IETF draft [Mail Autoconfig](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-autoconfig/00/) represents another exploration towards unified standards. We hope this paper will stimulate community discussion and help build consensus toward formal standardization. Let's work together to create a more secure email communication environment.
