# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-11-03

"""CloudLinux Build System RPM spec file parser."""

from collections import namedtuple
import re

from castor.utils.rpm_utils import string_to_version

__all__ = ["RPMChangelogRecord"]


class RPMChangelogRecord(
    namedtuple("RPMChangelogRecord", ["date", "packager", "text"])
):
    @staticmethod
    def generate(date, user_name, user_email, evr, text):
        """
        An alternative initialization method with EVR argument.

        Parameters
        ----------
        date : datetime.date
            Changelog record datestamp.
        user_name : str
            User name.
        user_email : str
            User e-mail address.
        evr : str
            EVR (epoch, version, release).
        text : str or list
            Changelog text.

        Returns
        -------
        RPMChangelogRecord
            Initialized changelog record.
        """
        packager = "{0} <{1}> - {2}".format(user_name, user_email, evr)
        text = [text] if isinstance(text, str) else text
        formatted_text = RPMChangelogRecord.format_changelog_text(text)
        return RPMChangelogRecord(date, packager, formatted_text)

    @staticmethod
    def format_changelog_text(text):
        """
        Formats a changelog text according to an RPM spec standards.

        Parameters
        ----------
        text : list of str
            Changelog text.

        Returns
        -------
        list of str
            Formatted changelog text.
        """
        formatted = []
        for line in text:
            if not line.startswith("-"):
                line = "- {0}".format(line)
            formatted.append(line)
        return formatted

    @property
    def evr(self):
        """
        Returns a package EVR (epoch, version and release) substring of a
        changelog record.

        Returns
        -------
        str or None
            Package EVR substring or None if there was no version
            information found.
        """
        re_rslt = re.search(r"[\s-]+(\d+[-\w:.]*)$", self.packager)
        return re_rslt.group(1) if re_rslt else None

    @property
    def epoch(self):
        """
        Returns a package epoch from a changelog record.

        Returns
        -------
        str or None
            Package epoch if a version information is present, None otherwise.
            Note: it will return "0" if epoch is not specified.
        """
        return string_to_version(self.evr)[0]

    @property
    def version(self):
        """
        Returns a package version from a changelog record.

        Returns
        -------
        str or None
            Package version if found.
        """
        return string_to_version(self.evr)[1]

    @property
    def release(self):
        """
        Returns a package release from a changelog record.

        Returns
        -------
        str or None
            Package release if found.
        """
        return string_to_version(self.evr)[2]

    def __str__(self):
        header = "* {0} {1}".format(self.date.strftime("%a %b %d %Y"), self.packager)
        return "{0}\n{1}".format(header, "\n".join(self.text))

    def __unicode__(self):
        header = "* {0} {1}".format(self.date.strftime("%a %b %d %Y"), self.packager)
        return "{0}\n{1}".format(header, "\n".join(self.text))
