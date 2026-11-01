from django import forms

from apps.accounts.models import User
from apps.labs.models import Accommodation, Lab

DT = forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M")


class StudentForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["index_number", "first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["index_number"].required = True
        self.fields["first_name"].required = True
        self.fields["last_name"].required = True

    def clean_index_number(self):
        value = self.cleaned_data["index_number"].strip()
        clash = User.objects.filter(username=value) | User.objects.filter(index_number=value)
        if clash.exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("A user with this index number already exists.")
        return value


class ImportForm(forms.Form):
    file = forms.FileField(
        help_text="CSV with a header row: index_number, first_name, last_name, "
                  "and optionally email, password.")

    def clean_file(self):
        f = self.cleaned_data["file"]
        if f.size > 2 * 1024 * 1024:
            raise forms.ValidationError("File too large (2 MB max).")
        return f


class SuspendForm(forms.Form):
    reason = forms.CharField(max_length=255)


class AccommodationForm(forms.ModelForm):
    class Meta:
        model = Accommodation
        fields = ["lab", "extra_minutes", "closes_at_override", "reason"]
        widgets = {"closes_at_override": DT}
        labels = {"lab": "Lab (blank = all labs)",
                  "closes_at_override": "New deadline (optional)"}

    def clean(self):
        data = super().clean()
        if not data.get("extra_minutes") and not data.get("closes_at_override"):
            raise forms.ValidationError("Give extra minutes, a new deadline, or both.")
        return data


class LabSettingsForm(forms.ModelForm):
    class Meta:
        model = Lab
        fields = ["published", "mode", "opens_at", "closes_at", "duration_minutes",
                  "max_attempts", "weight", "show_feedback"]
        widgets = {"opens_at": DT, "closes_at": DT}

    def clean(self):
        data = super().clean()
        o, c = data.get("opens_at"), data.get("closes_at")
        if o and c and c <= o:
            raise forms.ValidationError("The lab must close after it opens.")
        return data


class GradeForm(forms.Form):
    score = forms.DecimalField(min_value=0, max_digits=6, decimal_places=2)
    feedback = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)

    def __init__(self, *args, max_points, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_points = max_points
        self.fields["score"].widget.attrs.update({"max": str(max_points), "step": "0.5"})

    def clean_score(self):
        score = self.cleaned_data["score"]
        if score > self.max_points:
            raise forms.ValidationError(f"Maximum is {self.max_points}.")
        return score
