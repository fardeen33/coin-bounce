class BlogdetailsDTO {
    constructor(blog){
        this._id = blog._id;
        this.title = blog.title;
        this.content = blog.content;
        this.photo = blog.photoPath;
        this.createdAt = blog.createdAt;
        this.authorName = blog.author.name;
        this.authorUserName = blog.author.username;
    }
}

module.exports = BlogdetailsDTO;
