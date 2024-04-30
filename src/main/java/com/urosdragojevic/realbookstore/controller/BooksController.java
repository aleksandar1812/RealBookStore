package com.urosdragojevic.realbookstore.controller;

import com.urosdragojevic.realbookstore.domain.*;
import com.urosdragojevic.realbookstore.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.nio.file.AccessDeniedException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Controller
public class BooksController {

    @Autowired
    private BookRepository bookRepository;

    @Autowired
    private GenreRepository genreRepository;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private RatingRepository ratingRepository;

    @Autowired
    private PersonRepository personRepository;

    @GetMapping({"/", "/books"})
    @PreAuthorize("hasAuthority('VIEW_BOOKS_LIST')")
    public String home(Model model) {
        model.addAttribute("books", bookRepository.getAll());
        return "books";
    }

    @GetMapping("/books/{id}")
    @PreAuthorize("hasAuthority('CREATE_BOOKS')")
    public String book(Model model, @PathVariable int id) {

        Book book = bookRepository.get(id);

        List<Genre> genres = genreRepository.getAllForBook(id);
        book.setGenres(genres);

        book.setRating(ratingRepository.getAll(id));
        book.setOverallRating(ratingRepository.getRatingForBook(id));

        List<Comment> comments = commentRepository.getAll(id);
        List<ViewComment> viewComments = new ArrayList<>();

        for (Comment comment : comments) {
            Person person = personRepository.get(String.valueOf(comment.getUserId()));
            viewComments.add(new ViewComment(person.getFirstName() + " " + person.getLastName(), comment.getComment()));
        }

        book.setComments(commentRepository.getAll(id));

        model.addAttribute("book", book);
        model.addAttribute("comments", viewComments);
        book.getRating()
                .stream()
                .filter(rating -> rating.getUserId() == 1)
                .findFirst()
                .ifPresent(rating -> model.addAttribute("userRating", rating.getRating()));
        return "book";
    }

    @GetMapping("/create-form")
    @PreAuthorize("hasAuthority('CREATE_BOOKS')")
    public String CreateForm(Model model) {
        model.addAttribute("genres", genreRepository.getAll());
        return "create-form";
    }

    @GetMapping(value = "/books/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_BOOKS_LIST')")
    public List<Book> search(@RequestParam("query") String query) throws SQLException {
        return bookRepository.search(query);
    }

    @PostMapping("/books")
    @PreAuthorize("hasAuthority('CREATE_BOOKS')")
    public String createBook(NewBook book) throws AccessDeniedException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        var poredi =  authentication.getPrincipal();
        if(!(poredi instanceof UserDetails)){
            try {
                throw new AccessDeniedException("Nije person klasa");
            } catch (AccessDeniedException e) {
                e.printStackTrace();
            }
        }
        var logovan = (UserDetails) poredi;
        try {
            var osoba = (personRepository.search(logovan.getUsername())).get(0);
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        boolean isAllowed = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("CREATE_BOOK"));
        if (!isAllowed){
            throw new AccessDeniedException("Forbidden");
        }
        List<Genre> genreList = this.genreRepository.getAll();
        List<Genre> genresToInsert = book.getGenres().stream().map(bookGenreId -> genreList.stream().filter(genre -> genre.getId() == bookGenreId).findFirst().get()).collect(Collectors.toList());
        long id = bookRepository.create(book, genresToInsert);
        return "redirect:/books?id=" + id;
    }
}
