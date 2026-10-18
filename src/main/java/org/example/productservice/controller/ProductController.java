package org.example.productservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Danh sách sản phẩm giả, không cần Database
    private final Map<Long, Product> products =
            new ConcurrentHashMap<>(Map.of(
                    1L, new Product(1L, "Laptop", 15000000),
                    2L, new Product(2L, "Phone", 8000000),
                    3L, new Product(3L, "Keyboard", 500000)
            ));

    // USER và ADMIN đều được xem danh sách
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<Product> getAllProducts() {

        return products.values()
                .stream()
                .sorted(Comparator.comparing(Product::id))
                .toList();
    }

    // Chỉ ADMIN được xóa sản phẩm
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteProduct(
            @PathVariable Long id
    ) {

        Product deleted = products.remove(id);

        if (deleted == null) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Không tìm thấy sản phẩm ID: " + id
            );
        }

        System.out.println(
                "ADMIN đã xóa sản phẩm ID: " + id
        );

        return ResponseEntity.noContent().build();
    }

    public record Product(
            Long id,
            String name,
            Integer price
    ) {
    }
}
