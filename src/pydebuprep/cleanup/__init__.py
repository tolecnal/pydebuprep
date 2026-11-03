"""pydebuprep-cleanup: purges old kernels, their modules and headers, directories they
leave behind, and the configuration of removed packages.

The one part of pydebuprep that changes the system, on purpose and only when asked
(--apply). `pydebuprep report` and `snapshot` never import it.
"""
