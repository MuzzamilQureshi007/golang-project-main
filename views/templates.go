package views

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
)

func Must(t Template, err error) Template {
	if err != nil {
		panic(err)
	}

	return t
}

func Parse(filepath string) (Template, error) {

	tpl, err := template.ParseFiles(filepath)
	if err != nil {
		return Template{}, fmt.Errorf("Parsing template %w", err)
	}
	return Template{
		HTMLTpl: tpl,
	}, nil

}

type Template struct {
	HTMLTpl *template.Template
}

func (t Template) Execute(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content_type", "text/html; charset=utf-8")
	// fmt.Fprint(w, "Home dd")
	err := t.HTMLTpl.Execute(w, data)
	if err != nil {
		// panic(err)
		log.Printf("parsing template %v", err)
		http.Error(w, "there was an error parsing the template", http.StatusInternalServerError)
		return
	}
}
