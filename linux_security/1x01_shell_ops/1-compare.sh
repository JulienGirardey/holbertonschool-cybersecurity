#!/bin/bash
diff <(cut -d: -f1 $1) <(cut -d: -f1 $1 | sort)
