from django import forms
from django.contrib.auth.forms import AuthenticationForm


class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Index number / username", max_length=150,
                               widget=forms.TextInput(attrs={"autofocus": True,
                                                             "autocomplete": "username"}))

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if user.suspended:
            raise forms.ValidationError(
                "This account is suspended. Please speak to the lecturer or a TA.",
                code="suspended",
            )
