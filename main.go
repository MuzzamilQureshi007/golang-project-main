package main

import (
	"mymodule/controllers"
	"mymodule/views"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	_ "github.com/go-chi/chi/v5"
)

type SomeType struct {
	Template views.Template
}

func (st SomeType) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	st.Template.Execute(w, nil)
}

func main() {

	router := chi.NewRouter()

	tpl := views.Must(views.Parse(filepath.Join("templates", "home.html")))

	router.Get("/", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "dashboard.html")))

	router.Get("/dashboard", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "signin.html")))

	router.Get("/signin", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "register.html")))

	router.Get("/register", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "signin.html")))

	router.Post("/register_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "dashboard.html")))

	router.Post("/signin_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "user.html")))

	router.Get("/All_user", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "update.html")))

	router.Get("/edit", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "dashboard.html")))

	router.Post("/edit_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "user.html")))

	router.Get("/delete", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "signin.html")))

	router.Get("/logout", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "manage_role.html")))

	router.Post("/edit_role_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "manage_role.html")))

	router.Get("/manage_role", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "posts.html")))

	router.Get("/All_posts", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "insert_post.html")))

	router.Get("/insert_post", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "posts.html")))

	router.Post("/insert_post_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "update_post.html")))

	router.Get("/edit_post", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "dashboard.html")))

	router.Post("/edit_post_process", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "posts.html")))

	router.Get("/delete_posts", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "contact.html")))

	router.Get("/contact", controllers.StaticHandler(tpl))

	tpl = views.Must(views.Parse(filepath.Join("templates", "about.html")))

	router.Get("/about", controllers.StaticHandler(tpl))

	// tpl = views.Must(views.Parse(filepath.Join("templates", "manage_role.html")))

	// router.Get("/manage_role_process", controllers.StaticHandler(tpl))

	// route.Post("/edit_role_process", controller s.StaticHandler(views.Must(views.Parse(filepath.Join("templates", "manage_role.gohtml")))))
	// http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.ListenAndServe(":200", router)

}
