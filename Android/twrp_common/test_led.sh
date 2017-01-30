#!/vendor/bin/busybox ash
echo 150 >/sys/class/timed_output/vibrator/enable
echo 0 >/sys/class/leds/led:rgb_red/brightness
echo 0 >/sys/class/leds/led:rgb_green/brightness
echo 255 >/sys/class/leds/led:rgb_blue/brightness
