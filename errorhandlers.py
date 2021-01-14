
# #Exception for 404 not found
class ResourceNotFound(Exception):
	def __init__(self, msg):
		self.msg = msg

#Exception for 400
class BadRequest(Exception):
	def __init__(self, msg):
		self.msg = msg

#Exception 500
class InternalServerError(Exception):
	def __init__(self,msg):
		self.msg = msg

class UserNotFound(ResourceNotFound):
	def __init__(self, msg):
		self.msg = msg

class DuplicateUser(BadRequest):
	def __init__(self, msg):
		self.msg = msg



