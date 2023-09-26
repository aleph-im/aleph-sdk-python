def test_object():
    account = Account()
    client = AlephClient(account)
    client.get_messages(...)

    my_posts = Post.objects.filter(sender="0x...")

    new_post = Post.objects.create(body="Hello, world!")
    new_post.save()


class Manager:
    pass


class PostManager(Manager):
    pass


class HttpPostManager(PostManager):
    def filter(self, **kwargs):
        query_filter = QueryFilter(**kwargs)
        pass

    def create(self, body: str):
        pass

    def save(self, post):
        pass


class SqliteCachedHttpManager(HttpPostManager):
    pass


class Post:
    objects: PostManager
    message: AlephMessage

    def __init__(self, manager: Optional[PostManager] = None):
        self.objects = PostManager()


class MyPost(Post):
    title: str
    number: int


Aleph
