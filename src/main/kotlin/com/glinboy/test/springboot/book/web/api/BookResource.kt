package com.glinboy.test.springboot.book.web.api

import com.glinboy.test.springboot.book.entity.Book
import com.glinboy.test.springboot.book.service.BookServiceApi
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException

@RestController
@RequestMapping("/api/v1/books")
@SecurityRequirement(name = "Bearer Authentication")
class BookResource(val bookService: BookServiceApi) {

    @GetMapping
    fun getBooks(@Parameter(hidden = true) pageable: Pageable): ResponseEntity<Page<Book>> =
        ResponseEntity.ok(bookService.getBooks(pageable))

    @GetMapping("{id}")
    fun getBook(@PathVariable id: Long): ResponseEntity<Book> =
        bookService.getBook(id)
            .map { ResponseEntity.ok(it) }
            .orElseGet { ResponseEntity.notFound().build() }

    @PostMapping
    fun addBook(@RequestBody book: Book): ResponseEntity<Book> =
        ResponseEntity(bookService.saveBook(book), HttpStatus.CREATED)

    @DeleteMapping("{id}")
    fun deleteBook(@PathVariable id: Long): ResponseEntity<Unit> {
        bookService.deleteBook(id)
        return ResponseEntity.noContent().build()
    }

    @PutMapping
    fun updateBook(@RequestBody book: Book): ResponseEntity<Book> {
        if (book.id == null) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Book should have ID to update")
        }
        return ResponseEntity.ok(bookService.saveBook(book))
    }
}
