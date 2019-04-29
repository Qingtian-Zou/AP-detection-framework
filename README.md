# Attack Pattern Detection Framework

## Framework Architecture

                                                                                           +--------------------------+
                                                                                           |                          |
                  +------------------------------------------------------------------------+  Attack pattern updater  |
                  |                                                                        |                          |
                  |                                                                        +-------------+------------+
                  |                                                                                      ^
                  v                                                                                      |
	+-------------+---------------+       +--------------------------+                     +-------------+------------+
	|                             |       |                          |                     |                          |
	|  Attack pattern repository  +------>+  Attack pattern parsers  +-------------------->+  Attack pattern matcher  +<--->  User
	|                             |       |                          |                     |                          |
	+-----------------------------+       +--------------------------+                     +-------------+------------+
                                                                                                         ^
                                                                                                         |
                                                                                                         |
                                                                                                         |
	+---------------------------+         +----------------+       +------------------------------+      |
	|                           |         |                |       |                              |      |
	|  System information data  +-------->+  Data parsers  +------>+  Attack technique detectors  +------+
	|                           |         |                |       |                              |
	+---------------------------+         +----------------+       +------------------------------+

## Sample Attack Pattern

	+---------------------+    +------------------------+    +----------------+    +-----------------+
	|                     |    |                        |    |                |    |                 |
	|  Drive-by-download  +--->+  Privilege escalation  +--->+  Hash dumping  +--->+  Pass the hash  |
	|                     |    |                        |    |                |    |                 |
	+---------------------+    +------------------------+    +----------------+    +-----------------+
