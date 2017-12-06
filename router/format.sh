#!/usr/bin/env bash
astyle --unpad-paren --indent=spaces=4 --add-brackets --style=java --pad-oper --break-blocks=all --align-pointer=type --add-brackets ./*.c ./*.h
