import logging
from datetime import datetime


class LoggingDateRotating(object):
    def __init__(self, path, name, format):
        self.path = path
        self.name = name
        self.filename = self.createFileName()
        self.logger = logging.getLogger(name)
        self.formatter = logging.Formatter(format)
        self.handler = logging.FileHandler(self.filename)
        self.level = logging.DEBUG
        self.date = datetime.now().date()

        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(self.level)
        self.logger.propagate = False

    def shouldRefreshFileHandler(self):
        if self.date < datetime.now().date():
            return True
        return False

    def refreshFileHandler(self):
        if self.handler:
            self.handler.close()
            self.logger.removeHandler(self.handler)
        self.filename = self.createFileName()
        self.handler = logging.FileHandler(self.filename, 'w')
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)

    def createFileName(self):
        return self.path + self.name + '_' + datetime.now().date().isoformat() + '.log'

    def getLogger(self):
        if self.shouldRefreshFileHandler():
            self.refreshFileHandler()
        return self.logger


