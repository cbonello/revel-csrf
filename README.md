revel-csrf
==========

`revel-csrf` implements Cross-Site Request Forgery (CSRF) attacks
prevention for the [Revel framework](https://github.com/robfig/revel).

Code is based on the `nosurf` package implemented by
[Justinas Stankevičius](https://github.com/justinas/nosurf).

## Limitations

Package does not yet include provision to exempt specific routes from
CSRF checks.

## Installation

    go get github.com/cbonello/revel-csrf

## Operating instructions

Simply call the CSRFFilter() filter from init.go:   

    package app

    import (
        "github.com/cbonello/revel-csrf"
        "github.com/robfig/revel"
    )

    func init() {
	    // Filters is the default set of global filters.
	    revel.Filters = []revel.Filter{
		    revel.PanicFilter,             // Recover from panics and display an error page instead.
		    revel.RouterFilter,            // Use the routing table to select the right Action
		    revel.FilterConfiguringFilter, // A hook for adding or removing per-Action filters.
		    revel.ParamsFilter,            // Parse parameters into Controller.Params.
		    revel.SessionFilter,           // Restore and write the session cookie.
		    revel.FlashFilter,             // Restore and write the flash cookie.
		     csrf.CSRFFilter,              // CSRF prevention.
		    revel.ValidationFilter,        // Restore kept validation errors and save new ones from cookie.
		    revel.I18nFilter,              // Resolve the requested language
		    revel.InterceptorFilter,       // Run interceptors around the action.
		    revel.ActionInvoker,           // Invoke the action.
	    }
    }

Insert a hidden input field named `csrf_token` in your forms.

    <form action="/Hello" method="POST">
        <input type="text" name="name" />
        <input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
        <button type="submit">Send</button>
    </form>

You can also use following javascript code to perform AJAX calls (jQuery 1.5 and newer).

    function csrfSafeMethod(method) {
        // HTTP methods that do not require CSRF protection.
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        crossDomain: false,
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type)) {
                xhr.setRequestHeader("X-CSRFToken", {{ .csrf_token }});
            }
        }
    });

A demo application is provided in the samples directory. To launch it:

    revel run github.com/cbonello/revel-csrf/samples/demo

## TODO

* Routes exemption.
* Logger.
* Unique token per-page.
* Configuration options.
* Test cases.
