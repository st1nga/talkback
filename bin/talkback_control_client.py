#!/usr/bin/env python
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Listen to the mq topic ob/studio<hostname>
#===========================================================================
# Modifications
#---------------------------------------------------------------------------

import paho.mqtt.client as mqtt
mqtt.Client.connected_flag = False
mqtt.Client.mqtt_result = 0
mqtt.Client.logger = 0
mqtt.Client.primary_studio = ''
mqtt.Client.this_studio = ''

import sys
import signal
import socket
import uuid
import time
from subprocess import Popen, PIPE, STDOUT

import configparser
import logging
from optparse import OptionParser
import platform

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Stops nasty message going to stdout :-) Unrequired prettyfication
#---------------------------------------------------------------------------
def signal_handler(sig, frame):
  print("Exiting due to control-c")
  sys.exit(0)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
def custom_logger(name, logger_level, config, log_to_screen):
    '''Custom logging module'''

    logger_level = logger_level.upper()

    formatter = logging.Formatter(fmt='%(asctime)s %(name)s:%(process)-5d %(levelname)-8s %(lineno)-4d: %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler(config.get("talkback_control_client", "log_file"), mode='a')
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
def connect_to_mosquitto(host, logger, config):

  mosquitto = mqtt.Client(client_id = "talkback_control_client_%s_%s" % (host, uuid.uuid4()), clean_session=True)
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
def on_connect(client, userdata, flags, rc):

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
    mqtt.Client.logger.error("systemctl failed. cmd = '%s'" % cmd)
  mqtt.Client.logger.debug("Done with bashit")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we receive a message from mqtt
#---------------------------------------------------------------------------
def on_message(client, userdata, message):

  payload = str(message.payload.decode("utf-8"))
  mqtt.Client.logger.info("Got a message! Topic '%s' = '%s'" % (message.topic, payload))

  host = socket.gethostname()
  mqtt.Client.logger.debug("This is host '%s'" % host)

#+
#Neded to think about out of order delivery
#-
  if message.topic == "ob/primary_studio":
    mqtt.Client.primary_studio = payload
  else:
    mqtt.Client.this_studio = payload

  if mqtt.Client.primary_studio != '' and mqtt.Client.this_studio != '':
    if mqtt.Client.this_studio == 'on':
      bashit("/bin/systemctl start talkback_rx")
      if mqtt.Client.primary_studio != host:
        bashit("/bin/systemctl start talkback_tx")
    else:
      bashit("/bin/systemctl stop talkback_tx")
      bashit("/bin/systemctl stop talkback_rx")

  mqtt.Client.logger.debug("All done")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# on_disconnect
#---------------------------------------------------------------------------
def on_disconnect(client, userdata, rc):
  mqtt.Client.logger.debug("Unexpected disconnection")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#MAIN Main main
#---------------------------------------------------------------------------
def main():

#+
#Parse the options passed
#-
  parser = OptionParser()
  parser.add_option("", "--logger-level", dest="logger_level",
    help="Log level: ERROR, WARNING, INFO, DEBUG")

  parser.add_option("", "--config", dest="config_file",
    help="Config file [Default=%default]", default="/root/talkback_control_client.conf")

  parser.add_option("", "--log-to-screen", action="store_true", dest="log_to_screen",
    help="Output log message to screen [Default=%default]")

  (options, args) = parser.parse_args()

#+
#Load the config file
#-
  config = configparser.ConfigParser()
  config.read(options.config_file)

  logger_level = config.get('talkback_control_client', 'logger_level')
  if options.logger_level is not None:
    logger_level = options.logger_level
#+
#Setup custom logging
#-
  logger = custom_logger(config.get('talkback_control_client', 'logger_name'), logger_level, config, options.log_to_screen)
  logger.info("Hello world! Python version = '%s'Config = '%s'. Log level = '%s'" % (platform.python_version(), options.config_file, logger_level))
  mqtt.Client.logger = logger

#+
#Catch control-c
#-
  signal.signal(signal.SIGINT, signal_handler)

#+
#Connect and subscribe to mosquitto, the MQTT broker
#-
  mosquitto = connect_to_mosquitto(socket.gethostname(), logger, config)

  host = socket.gethostname()
  mqtt.Client.logger.debug("This is host '%s'" % host)

  mosquitto.subscribe([("ob/studio/%s" % host, 2), ("ob/primary_studio", 2)])

#+
#Tell mosquitto to loop waiting for messages
#-
  logger.debug("About to loop forever")
  mosquitto.loop_forever()

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
