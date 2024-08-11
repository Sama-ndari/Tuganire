from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField(validators=[DataRequired()],
                        render_kw={"placeholder": "Enter your Post title here"})
    subtitle = StringField(validators=[DataRequired()],
                           render_kw={"placeholder": "Enter your Post subtitle here"})
    img_url = StringField("Post Image URL",
                          validators=[DataRequired(), URL()])
    body = CKEditorField("Post Content",
                         validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired()],
                        render_kw={"placeholder": "Enter your Email here"})
    password = PasswordField(validators=[DataRequired()],
                             render_kw={"placeholder": "Enter your Password here"})
    name = StringField(validators=[DataRequired()],
                       render_kw={"placeholder": "Enter your Name here"})
    submit = SubmitField("SIGN ME UP")


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()],
                        render_kw={"placeholder": "Enter your Email here"})
    password = PasswordField(validators=[DataRequired()],
                             render_kw={"placeholder": "Enter your Password here"})
    submit = SubmitField("SIGN ME UP")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("SUBMIT COMMENT")
