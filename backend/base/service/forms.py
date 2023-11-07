from django import forms

class PickleUploadForm(forms.Form):
    pickle_file = forms.FileField(label='Pickle 파일 업로드')

    def clean_pickle_file(self):
        uploaded_file = self.cleaned_data['pickle_file']
        if not uploaded_file.name.endswith('.pkl'):
            raise forms.ValidationError('잘못된 파일 형식입니다. .pkl 파일을 업로드하세요.')
        return uploaded_file