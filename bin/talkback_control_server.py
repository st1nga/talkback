#!/usr/bin/env python
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Listen to mosuitto topics and route audui back to remote studios
#===========================================================================
# Modifications
#---------------------------------------------------------------------------

import paho.mqtt.client as mqtt
mqtt.Client.connected_flag = False
mqtt.Client.mqtt_result = 0
mqtt.Client.logger = 0
mqtt.Client.talkback = []
mqtt.Client.todo = []
mqtt.Client.jackd = 0
mqtt.Client.primary = ''

import jack

from subprocess import Popen, PIPE, STDOUT

import signal
import uuid
import logging
from optparse import OptionParser
import sys
import configparser
import platform
import time

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Stops nasty message going to stdout :-) Unrequired prettyfication
#---------------------------------------------------------------------------
def signal_handler(sig, frame):
  print("Exiting due to control-c")
  sys.exit(0)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
def custom_logger(name, logger_level, config, log_to_screen):

  logger_level = logger_level.upper()

  formatter = logging.Formatter(fmt='%(asctime)s %(name)s:%(process)-5d %(levelname)-8s %(lineno)-4d: %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
  handler = logging.FileHandler(config.get("talkback_control",  "log_file"), mode='a')
  handler.setFormatter(formatter)
  logger = logging.getLogger(name)
  logger.setLevel(logging.getLevelName(logger_level))
  logger.addHandler(handler)

  if log_to_screen == True:
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger.addHandler(screen_handler)

  return logger

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#connect to mosquitto MQTT
#---------------------------------------------------------------------------
def connect_to_mosquitto(logger, config):

  mosquitto = mqtt.Client(client_id = "talkback_control_%s" % uuid.uuid4(), clean_session=False)
  mosquitto.username_pw_set(username = config.get("mqtt", "username"), password = config.get("mqtt", "password"))
  mosquitto.on_connect = on_connect
  mosquitto.on_subscribe = on_subscribe
  mosquitto.on_message = on_message
  mosquitto.on_disconnect = on_disconnect
  mosquitto.connect(config.get("mqtt", "host"), int(config.get("mqtt", "port")))

  return mosquitto

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we sucessfully connect to mqtt broker
#---------------------------------------------------------------------------
def on_connect(mosquitto, userdata, flags, rc):

  mqtt.Client.mqtt_result = rc

  if mqtt.Client.mqtt_result == 0:
    mqtt.Client.connected_flag = True
    mqtt.Client.logger.debug("Connected sucessfully to Mosquitto")
  else:
    mqtt.Client.logger.debug("Bad mosquitto connection: %s"  % rc)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we sucessfully subscribe to a topic
#---------------------------------------------------------------------------
def on_subscribe(client, userdata, mid, granted_qos):

  mqtt.Client.logger.debug("We have subscribed")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#Run a bash command
#---------------------------------------------------------------------------
def bashit(cmd):
  mqtt.Client.logger.debug("bashit. cmd = '%s'" % cmd)
  p = Popen(cmd, stderr=STDOUT, stdout=PIPE, shell=True)
  remote_cmd_returned = p.communicate()[0]
  remote_cmd_returned = remote_cmd_returned.decode().rstrip()
  if remote_cmd_returned != "":
    mqtt.Client.logger.debug("systemctl failed. cmd = '%s'" % cmd)
  mqtt.Client.logger.debug("Done with bashit")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Link the TB jack channels together
# 00 link is tantive to remote
# 11 link is remote to tantive
#---------------------------------------------------------------------------
def link_obs():

  mqtt.Client.logger.debug(mqtt.Client.primary)

#+
#Connect all the talkback clients to each other
  for tb_1 in mqtt.Client.talkback:
    for tb_2 in mqtt.Client.talkback:
      if tb_1 != tb_2 and tb_1 !=  mqtt.Client.primary:
        mqtt.Client.logger.debug("Guest mqtt.Client.jackd.connect('%s_tb_11:out_%s_tb_11_1', '%s_tb_00:in_%s_tb_00_1')" % (tb_1, tb_1, tb_2, tb_2))
        mqtt.Client.logger.debug("Guest mqtt.Client.jackd.connect('%s_tb_11:out_%s_tb_11_2', '%s_tb_00:in_%s_tb_00_2')" % (tb_1, tb_1, tb_2, tb_2))

#+
#Connect the primary stodio fedd to all the talkback clients
#-
  for tb in mqtt.Client.talkback:
    if tb != mqtt.Client.primary:
      mqtt.Client.logger.debug("mqtt.Client.jackd.connect('openob_%s:out_openob_%s_1', '%s_tb_00:in_%s_tb_00_1')" % (mqtt.Client.primary, mqtt.Client.primary, tb, tb))
      mqtt.Client.logger.debug("mqtt.Client.jackd.connect('openob_%s:out_openob_%s_2', '%s_tb_00:in_%s_tb_00_2')" % (mqtt.Client.primary, mqtt.Client.primary, tb, tb))

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Process the on air TB studios.
# mqtt does not order topics so we can get info before we know what the primary studio is
#---------------------------------------------------------------------------
def do_todo():

  for tb_1 in mqtt.Client.todo:
    mqtt.Client.talkback.append(tb_1)
    for tb_2 in mqtt.Client.todo:
      if tb_1 != tb_2 and tb_1 !=  mqtt.Client.primary:
       mqtt.Client.logger.debug("Guest mqtt.Client.jackd.connect('%s_tb_11:out_%s_tb_11_1', '%s_tb_00:in_%s_tb_00_1')" % (tb_1, tb_1, tb_2, tb_2))
       mqtt.Client.logger.debug("Guest mqtt.Client.jackd.connect('%s_tb_11:out_%s_tb_11_2', '%s_tb_00:in_%s_tb_00_2')" % (tb_1, tb_1, tb_2, tb_2))

  for tb in mqtt.Client.talkback:
    if tb != mqtt.Client.primary:
      mqtt.Client.logger.debug("mqtt.Client.jackd.connect('openob_%s:out_openob_%s_1', '%s_tb_00:in_%s_tb_00_1')" % (mqtt.Client.primary, mqtt.Client.primary, tb, tb))
      mqtt.Client.logger.debug("mqtt.Client.jackd.connect('openob_%s:out_openob_%s_2', '%s_tb_00:in_%s_tb_00_2')" % (mqtt.Client.primary, mqtt.Client.primary, tb, tb))

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we receive a message from mqtt
#---------------------------------------------------------------------------
def on_message(client, userdata, message):

  mqtt.Client.logger.debug("Topic='%s', payload='%s'" % (message.topic, str(message.payload.decode("utf-8"))))

  if message.topic == 'ob/primary_studio':
    mqtt.Client.logger.debug("todo = %s" % mqtt.Client.todo)
    mqtt.Client.primary = str(message.payload.decode("utf-8"))
    if str(message.payload.decode("utf-8")) != '':
      do_todo()
  else:
    junk, junk, topic = message.topic.split('/')
    payload = str(message.payload.decode("utf-8"))
    if payload == 'on':
      if mqtt.Client.primary != '':
        mqtt.Client.talkback.append(topic)
        bashit("/bin/systemctl start openob_tb_tx_%s" % topic)
        bashit("/bin/systemctl start openob_tb_rx_%s" % topic)
        if len(mqtt.Client.talkback) > 1:
          mqtt.Client.logger.debug("More than 1 talkback studio enabled, link them all up")
          link_obs()
    else:
      if topic in mqtt.Client.talkback:
        mqtt.Client.talkback.remove(topic)

      bashit("/bin/systemctl stop openob_tb_tx_%s" % topic)
      bashit("/bin/systemctl stop openob_tb_rx_%s" % topic)

  if mqtt.Client.primary == '' and payload == 'on':
    mqtt.Client.todo.append(topic)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# on_disconnect
#---------------------------------------------------------------------------
def on_disconnect(client, userdata, rc):
  mqtt.Client.logger.debug("Unexpected disconnection")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#main Main MAIN
#---------------------------------------------------------------------------
def main():

#+
#Parse the options passed
#-
  parser = OptionParser()
  parser.add_option("", "--logger-level", dest="logger_level",
                    help="Log level: ERROR, WARNING, INFO, DEBUG")
  parser.add_option("", "--log-to-screen", action="store_true", dest="log_to_screen",
    help="Output log message to screen [Default=%default]", default=False)

  parser.add_option("", "--config", dest="config_file",
    help="Config file [Default=%default]", default="/etc/talkback_control.conf")

  (options, args) = parser.parse_args()

#+
#Load the config file
#-
  config = configparser.ConfigParser()
  mqtt.Client.config = config
  config.read(options.config_file)

  logger_level = config.get('talkback_control', 'logger_level')
  if options.logger_level is not None:
    logger_level = options.logger_level

#+
#Setup custom logging
#-
  logger = custom_logger(config.get('talkback_control', 'logger_name'), logger_level, config, options.log_to_screen)
  mqtt.Client.logger = logger
  logger.info("Hello world! Python version = '%s'Config = '%s'. Log level = '%s'" % (platform.python_version(), options.config_file, logger_level))

#+
#Connect and activate jackd connection
#-
  mqtt.Client.jackd = jack.Client('talkback_control')
  mqtt.Client.jackd.activate()
  
#+
#Catch control-c
#-
  signal.signal(signal.SIGINT, signal_handler)

#+
#Connect to mosquitto, the MQTT broker
#-
  mosquitto = connect_to_mosquitto(logger, config)
  (res,mid) = mosquitto.subscribe([("ob/studio/+", 1), ("ob/primary_studio", 1)])

#+
#Tell mosquitto to loop waiting for messages
#-
  mosquitto.loop_forever()

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
if __name__ == "__main__":
#    exit()
    main()
